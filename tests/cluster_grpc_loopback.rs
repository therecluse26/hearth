//! HEA-612: 3-node loopback integration test for the gRPC peer transport.
//!
//! Spins up three `ClusterEngine::build_clustered` instances on `127.0.0.1`
//! loopback addresses, each with its own mTLS identity signed by a throwaway
//! CA generated in a tempdir, bootstraps a Raft cluster from node 1, writes
//! 10 KV entries to the leader, and asserts every node converges on the same
//! state via real gRPC + mTLS round-trips.
//!
//! Complements `tests/cluster_smoke.rs`, which exercises the same surface area
//! through the in-process `MemRouter` — this test is the first one that
//! validates the network layer end-to-end on real sockets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::cluster::{serve, ClusterEngine, HearthNode};
use hearth::config::ClusterConfig;
use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tempfile::TempDir;
use uuid::Uuid;

// ── Throwaway mTLS bundle ────────────────────────────────────────────────────

/// Generates one self-signed CA plus `n_nodes` leaf certs valid for
/// `127.0.0.1` and `localhost`, writes them as PEM files under `dir`, and
/// returns `(ca_path, [(cert_path, key_path); n_nodes])`.
///
/// Mirrors the rcgen 0.13 pattern already established in `tests/tls.rs` so
/// the test follows the codebase's existing cert convention.
fn generate_cluster_certs(dir: &Path, n_nodes: usize) -> (PathBuf, Vec<(PathBuf, PathBuf)>) {
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("ca keygen");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write ca cert");

    let mut leafs = Vec::with_capacity(n_nodes);
    for i in 1..=n_nodes {
        let leaf_params = rcgen::CertificateParams::new(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("leaf params");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf keygen");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf sign");

        let cert_path = dir.join(format!("node-{i}.crt.pem"));
        let key_path = dir.join(format!("node-{i}.key.pem"));
        std::fs::write(&cert_path, leaf_cert.pem()).expect("write leaf cert");
        std::fs::write(&key_path, leaf_key.serialize_pem()).expect("write leaf key");

        leafs.push((cert_path, key_path));
    }
    (ca_path, leafs)
}

// ── Free-port discovery ──────────────────────────────────────────────────────

/// Pre-binds `n` listeners on `127.0.0.1:0` to discover OS-assigned ports,
/// then drops the listeners so the test's gRPC servers can re-bind. There is
/// a small race window between drop and re-bind, but acceptable for an
/// integration test in a controlled environment.
fn pick_free_loopback_ports(n: usize) -> Vec<u16> {
    use std::net::TcpListener;
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        ports.push(l.local_addr().expect("local_addr").port());
        listeners.push(l);
    }
    drop(listeners);
    ports
}

// ── Test fixture ─────────────────────────────────────────────────────────────

struct TestCluster {
    engines: Vec<Arc<ClusterEngine>>,
    server_handles: Vec<tokio::task::JoinHandle<()>>,
    // Held to keep cert + data files alive for the lifetime of the test.
    _tempdir: TempDir,
}

impl TestCluster {
    /// Builds an n-node loopback cluster: generates certs, spawns each
    /// node's gRPC server, bootstraps membership from node 1, and returns
    /// once `initialize_cluster` has been accepted.
    async fn build(n: usize) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let (ca_path, leaf_certs) = generate_cluster_certs(tempdir.path(), n);
        let ports = pick_free_loopback_ports(n);

        let mut engines = Vec::with_capacity(n);
        let mut server_handles = Vec::with_capacity(n);
        let mut configs = Vec::with_capacity(n);

        for i in 0..n {
            let node_id = (i + 1) as u64;
            let data_dir = tempdir.path().join(format!("node-{node_id}-data"));
            std::fs::create_dir_all(&data_dir).expect("create data dir");

            let storage_cfg = StorageConfig::dev(data_dir);
            let storage = Arc::new(
                EmbeddedStorageEngine::open(storage_cfg.clone()).expect("open storage"),
            );

            let (cert_path, key_path) = leaf_certs[i].clone();
            let cluster_cfg = ClusterConfig {
                node_id,
                peer_address: format!("127.0.0.1:{}", ports[i]),
                peers: vec![],
                tls_cert_path: cert_path,
                tls_key_path: key_path,
                tls_ca_cert_path: ca_path.clone(),
                // Generous so the lag-monitor doesn't gate `get()` during the
                // brief replication window after the writes burst.
                read_lag_threshold_ms: Some(10_000),
            };

            let engine =
                ClusterEngine::build_clustered(storage, &cluster_cfg, &storage_cfg)
                    .await
                    .expect("build_clustered");
            let engine = Arc::new(engine);

            let server_engine = Arc::clone(&engine);
            let serve_cfg = cluster_cfg.clone();
            let handle = tokio::spawn(async move {
                // serve() returns when the underlying tonic Server stops.
                // Errors during forced shutdown are uninteresting for the test.
                let _ = serve(&serve_cfg, server_engine).await;
            });

            engines.push(engine);
            configs.push(cluster_cfg);
            server_handles.push(handle);
        }

        // Give every server a moment to bind its TCP listener before the
        // bootstrap RPC tries to reach the peers.
        tokio::time::sleep(Duration::from_millis(400)).await; // AUDIT: justified-sleep: gRPC listeners need OS scheduling time to bind before the bootstrap RPC attempts connections

        let mut members = BTreeMap::new();
        for cfg in &configs {
            members.insert(
                cfg.node_id,
                HearthNode { addr: cfg.peer_address.clone() },
            );
        }
        engines[0]
            .initialize_cluster(members)
            .await
            .expect("initialize_cluster from node 1");

        Self {
            engines,
            server_handles,
            _tempdir: tempdir,
        }
    }

    /// Polls every node's metrics until at least one node reports a stable
    /// leader (and the leader sees itself as the leader). Panics on timeout.
    async fn wait_for_leader(&self, timeout: Duration) -> u64 {
        let start = Instant::now();
        loop {
            for engine in &self.engines {
                let Some(metrics) = engine.raft_metrics() else { continue };
                let Some(leader) = metrics.current_leader else { continue };
                // Confirm the elected leader also reports itself as leader —
                // a freshly-elected node briefly disagrees with its followers.
                let self_view = self
                    .engines
                    .iter()
                    .find_map(|e| e.raft_metrics().filter(|m| m.id == leader));
                if let Some(m) = self_view {
                    if m.current_leader == Some(leader) {
                        return leader;
                    }
                }
            }
            if start.elapsed() > timeout {
                for engine in &self.engines {
                    if let Some(m) = engine.raft_metrics() {
                        eprintln!(
                            "node {} state={:?} current_leader={:?}",
                            m.id, m.state, m.current_leader
                        );
                    }
                }
                panic!("no leader elected within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await; // AUDIT: justified-sleep: poll interval inside leader-election loop; openraft exposes no ready-signal channel
        }
    }

    fn engine_for(&self, node_id: u64) -> &Arc<ClusterEngine> {
        self.engines
            .iter()
            .find(|e| {
                e.raft_metrics()
                    .map(|m| m.id == node_id)
                    .unwrap_or(false)
            })
            .expect("engine present for node id")
    }

    /// Best-effort cleanup. Tempdir Drop closes log files; aborting the
    /// server tasks prevents the test process from waiting on them.
    fn shutdown(self) {
        for h in self.server_handles {
            h.abort();
        }
    }
}

// ── Test: 3-node gRPC loopback ───────────────────────────────────────────────

/// Per HEA-612 narrowed acceptance criteria:
///
/// 1. Spin up 3 `build_clustered` instances on loopback with self-signed certs
/// 2. Bootstrap from node 1
/// 3. Wait for leader election via `raft_metrics().current_leader`
/// 4. Write 10 puts on the leader
/// 5. Every node reports `last_applied >= 10` and `get()` returns the same values
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn three_node_grpc_loopback_replicates_ten_writes() {
    // rustls 0.23 requires a process-wide CryptoProvider to be installed
    // before any TLS handshake. The codebase pairs `tonic` with the
    // `tls-ring` feature, so use the ring provider to stay consistent with
    // `src/protocol/tls.rs`. `install_default` is one-shot per process; the
    // `Err` return on a repeat install is uninteresting for the test.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = TestCluster::build(3).await;

    // Election timeouts are 1500–3000 ms; 15 s margin tolerates a slow runner.
    let leader_id = cluster
        .wait_for_leader(Duration::from_secs(15))
        .await;
    assert!(
        (1..=3).contains(&leader_id),
        "elected leader {leader_id} outside expected range 1..=3"
    );

    let leader = cluster.engine_for(leader_id);
    let realm = RealmId::new(Uuid::new_v4());

    for i in 0..10u32 {
        let key = format!("k{i}");
        let val = format!("v{i}");
        leader
            .put(&realm, key.as_bytes(), val.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("put {key} on leader {leader_id} failed: {e}"));
    }

    // Wait for every node to catch up to the LEADER's last_applied index.
    //
    // A hard-coded `>= 10` check is wrong: openraft writes a membership entry
    // (index 1) at `initialize_cluster` and a blank NoOp (index 2) on leader
    // election, so the 10 client writes land at indices 3..=12. Comparing to
    // the leader's high-water mark sidesteps that arithmetic and works for
    // any future prelude-entry count.
    //
    // Spec acceptance requires `last_applied >= 10`; the stricter
    // leader-parity check naturally implies it once 10 puts have settled.
    let leader_target = leader
        .raft_metrics()
        .and_then(|m| m.last_applied.map(|l| l.index))
        .expect("leader has last_applied after 10 puts");
    assert!(
        leader_target >= 10,
        "leader last_applied {leader_target} < 10 — expected at least one entry per put"
    );

    let converge_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let all_caught_up = cluster.engines.iter().all(|engine| {
            engine
                .raft_metrics()
                .and_then(|m| m.last_applied.map(|l| l.index))
                .unwrap_or(0)
                >= leader_target
        });
        if all_caught_up {
            break;
        }
        if Instant::now() > converge_deadline {
            for engine in &cluster.engines {
                if let Some(m) = engine.raft_metrics() {
                    eprintln!(
                        "node {} last_applied={:?} last_log_index={:?}",
                        m.id,
                        m.last_applied.map(|l| l.index),
                        m.last_log_index
                    );
                }
            }
            panic!(
                "replication did not converge to last_applied >= {leader_target} within 10 s"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await; // AUDIT: justified-sleep: poll interval inside replication-convergence loop; log commit is async with no notification hook
    }

    // Per-node read consistency: every key must be present and equal on each
    // node, regardless of leader/follower role.
    for engine in &cluster.engines {
        let node_id = engine.raft_metrics().expect("metrics").id;
        for i in 0..10u32 {
            let key = format!("k{i}");
            let expected = format!("v{i}");
            let got = engine
                .get(&realm, key.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("get {key} on node {node_id} failed: {e}"));
            assert_eq!(
                got.as_deref(),
                Some(expected.as_bytes()),
                "node {node_id} returned {got:?} for {key}, expected {expected}"
            );
        }
    }

    cluster.shutdown();
}
