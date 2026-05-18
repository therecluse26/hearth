//! Cluster engine: public-facing storage wrapper with single-node bypass.
//!
//! [`ClusterEngine`] routes reads and writes through Raft when cluster mode
//! is active. In single-node mode all calls go directly to the inner
//! [`EmbeddedStorageEngine`] with zero overhead.
//!
//! ## Write path (cluster mode)
//! Every mutation creates a [`RaftCommand`] carrying a `leader_timestamp`
//! stamped at proposal time, proposes it via `Raft::client_write`, and blocks
//! until quorum commit. If this node is not the leader the caller receives
//! [`ClusterError::NotLeader`] with the leader's address for redirect.
//!
//! ## Read path (cluster mode)
//! A background task updates [`ClusterEngine::reads_allowed`] every 50 ms by
//! comparing `last_log_index` vs `last_applied` log indices. Reads check the
//! flag; if `false` the caller receives [`ClusterError::ReplicationLagExceeded`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use openraft::RaftMetrics;
use openraft::error::{ClientWriteError, RaftError};
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use openraft::{Config as RaftConfig, EntryPayload};
use tokio::task::spawn_blocking;
use tracing::{info, warn};

use crate::cluster::log_store::HearthLogStore;
use crate::cluster::network::HearthNetworkFactory;
use crate::cluster::server::IncomingRpcDispatch;
use crate::cluster::state_machine::HearthStateMachine;
use crate::cluster::types::{HearthNode, HearthRaftConfig, RaftCommand};
use crate::config::ClusterConfig;
use crate::core::RealmId;
use crate::storage::{EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine};

// ── Error types ───────────────────────────────────────────────────────────────

/// Error produced by cluster-layer storage operations.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// This node is not the Raft leader; clients should redirect.
    #[error("not the leader; redirect to {leader_addr}")]
    NotLeader { leader_addr: String },

    /// Follower replication lag exceeds the configured threshold.
    #[error("replication lag exceeded; redirect to {leader_addr}")]
    ReplicationLagExceeded { leader_addr: String },

    /// Underlying storage returned an error.
    #[error("storage: {0}")]
    Storage(#[from] crate::storage::StorageError),

    /// Raft or runtime error.
    #[error("raft: {0}")]
    Raft(String),
}

/// Error produced when building a [`ClusterEngine`].
#[derive(Debug, thiserror::Error)]
pub enum ClusterBuildError {
    #[error("failed to open Raft log store: {0}")]
    LogStore(String),
    #[error("failed to read TLS material: {0}")]
    Tls(#[from] std::io::Error),
    #[error("failed to initialise Raft: {0}")]
    RaftInit(String),
}

// ── ClusterEngine ─────────────────────────────────────────────────────────────

/// Public-facing storage wrapper that makes the cluster layer invisible in
/// single-node mode and routes traffic correctly in cluster mode.
pub struct ClusterEngine {
    inner: Arc<EmbeddedStorageEngine>,
    /// `None` in single-node mode — no Raft overhead, no port allocation.
    raft: Option<openraft::Raft<HearthRaftConfig>>,
    /// Follower reads are allowed when `true`. Updated every 50 ms by the
    /// background lag-monitor task in cluster mode.
    reads_allowed: Arc<AtomicBool>,
    /// Maximum acceptable replication lag in milliseconds (default 500).
    read_lag_threshold_ms: u64,
}

impl ClusterEngine {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Build a single-node engine (no Raft overhead, direct storage calls).
    pub fn single_node(inner: Arc<EmbeddedStorageEngine>) -> Self {
        Self {
            inner,
            raft: None,
            reads_allowed: Arc::new(AtomicBool::new(true)),
            read_lag_threshold_ms: 500,
        }
    }

    /// Build a full cluster-mode engine from config.
    ///
    /// Opens the Raft log store at `{storage_config.data_dir}/raft.db`,
    /// reads TLS credentials from the paths in `config`, creates a Raft
    /// instance, and spawns the background lag-monitor task.
    pub async fn build_clustered(
        inner: Arc<EmbeddedStorageEngine>,
        config: &ClusterConfig,
        storage_config: &StorageConfig,
    ) -> Result<Self, ClusterBuildError> {
        let raft_db_path = storage_config.data_dir.join("raft.db");
        let log_store = HearthLogStore::open(&raft_db_path)
            .map_err(|e| ClusterBuildError::LogStore(e.to_string()))?;

        let sm_engine: Arc<dyn StorageEngine> = Arc::clone(&inner) as Arc<dyn StorageEngine>;
        let state_machine = HearthStateMachine::new(sm_engine, storage_config.clone());

        let cert_pem = tokio::fs::read(&config.tls_cert_path).await?;
        let key_pem = tokio::fs::read(&config.tls_key_path).await?;
        let ca_pem = tokio::fs::read(&config.tls_ca_cert_path).await?;
        let network_factory = HearthNetworkFactory::new(cert_pem, key_pem, ca_pem);

        let raft_config = Arc::new(
            RaftConfig {
                heartbeat_interval: 500,
                election_timeout_min: 1500,
                election_timeout_max: 3000,
                ..RaftConfig::default()
            }
            .validate()
            .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?,
        );

        let raft = openraft::Raft::<HearthRaftConfig>::new(
            config.node_id,
            raft_config,
            network_factory,
            log_store,
            state_machine,
        )
        .await
        .map_err(|e| ClusterBuildError::RaftInit(e.to_string()))?;

        let threshold = config.read_lag_threshold_ms.unwrap_or(500);
        let reads_allowed = Arc::new(AtomicBool::new(true));
        let reads_flag = Arc::clone(&reads_allowed);
        let raft_for_monitor = raft.clone();

        tokio::spawn(async move {
            run_lag_monitor(raft_for_monitor, reads_flag, threshold).await;
        });

        info!(
            node_id = config.node_id,
            peer_address = %config.peer_address,
            read_lag_threshold_ms = threshold,
            "ClusterEngine initialised in cluster mode"
        );

        Ok(Self {
            inner,
            raft: Some(raft),
            reads_allowed,
            read_lag_threshold_ms: threshold,
        })
    }

    // ── Cluster initialisation ────────────────────────────────────────────────

    /// Bootstrap a brand-new cluster with the given membership.
    ///
    /// Call only on the designated bootstrap node. Other nodes join via the
    /// normal Raft membership protocol after the cluster is formed.
    pub async fn initialize_cluster(
        &self,
        members: BTreeMap<u64, HearthNode>,
    ) -> Result<(), ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("cannot initialise cluster on a single-node engine".to_string())
        })?;
        raft.initialize(members)
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    /// Returns a snapshot of the current Raft metrics (cluster mode only).
    pub fn raft_metrics(&self) -> Option<RaftMetrics<u64, HearthNode>> {
        self.raft.as_ref().map(|r| r.metrics().borrow().clone())
    }

    /// Configured replication-lag threshold in milliseconds.
    pub fn read_lag_threshold_ms(&self) -> u64 {
        self.read_lag_threshold_ms
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn current_leader_addr(&self) -> String {
        let Some(raft) = &self.raft else {
            return "unknown".to_string();
        };
        let metrics = raft.metrics().borrow().clone();
        let Some(leader_id) = metrics.current_leader else {
            return "unknown".to_string();
        };
        for (id, node) in metrics.membership_config.nodes() {
            if *id == leader_id {
                return node.addr.clone();
            }
        }
        "unknown".to_string()
    }

    /// Wall-clock microseconds since UNIX epoch — embedded in write commands
    /// as `leader_timestamp` so all nodes apply the same timestamp.
    fn leader_timestamp_now() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64
    }

    /// Returns `true` if reads should be served.
    ///
    /// Single-node: always true. Cluster: gated by the lag-monitor flag.
    fn reads_ok(&self) -> bool {
        self.raft.is_none() || self.reads_allowed.load(Ordering::Relaxed)
    }

    /// Propose a [`RaftCommand`] and block until quorum commit.
    async fn propose(&self, cmd: RaftCommand) -> Result<(), ClusterError> {
        let raft = self.raft.as_ref().ok_or_else(|| {
            ClusterError::Raft("propose called on single-node engine".to_string())
        })?;

        raft.client_write(cmd).await.map(|_| ()).map_err(|e| match e {
            RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)) => {
                let addr = fwd
                    .leader_node
                    .map(|n| n.addr)
                    .unwrap_or_else(|| "unknown".to_string());
                ClusterError::NotLeader { leader_addr: addr }
            }
            other => ClusterError::Raft(other.to_string()),
        })
    }

    // ── Async storage API ─────────────────────────────────────────────────────

    /// Retrieve a single value. Checks the lag flag in cluster mode.
    pub async fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ClusterError> {
        if !self.reads_ok() {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: self.current_leader_addr(),
            });
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        spawn_blocking(move || inner.get(&realm_id, &key))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Insert or update a key-value pair.
    ///
    /// In cluster mode the write is proposed through Raft with an embedded
    /// `leader_timestamp`. Returns `NotLeader` if this node is not the leader.
    pub async fn put(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Put {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                    value: value.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        let value = value.to_vec();
        spawn_blocking(move || inner.put(&realm_id, &key, &value))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Delete a key. In cluster mode proposes through Raft.
    pub async fn delete(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Delete {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    key: key.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let key = key.to_vec();
        spawn_blocking(move || inner.delete(&realm_id, &key))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Scan a key range. Checks the lag flag in cluster mode.
    pub async fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, ClusterError> {
        if !self.reads_ok() {
            return Err(ClusterError::ReplicationLagExceeded {
                leader_addr: self.current_leader_addr(),
            });
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let start = start.to_vec();
        let end = end.to_vec();
        spawn_blocking(move || inner.scan(&realm_id, &start, &end))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }

    /// Atomically write a batch of key-value pairs.
    ///
    /// In cluster mode the entire batch is proposed as a single `Batch` command
    /// so followers apply it atomically.
    pub async fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), ClusterError> {
        if self.raft.is_some() {
            return self
                .propose(RaftCommand::Batch {
                    leader_timestamp: Self::leader_timestamp_now(),
                    realm: realm_id.clone(),
                    entries: entries.to_vec(),
                })
                .await;
        }
        let inner = Arc::clone(&self.inner);
        let realm_id = realm_id.clone();
        let entries = entries.to_vec();
        spawn_blocking(move || inner.put_batch(&realm_id, &entries))
            .await
            .map_err(|e| ClusterError::Raft(e.to_string()))?
            .map_err(ClusterError::Storage)
    }
}

// ── IncomingRpcDispatch ───────────────────────────────────────────────────────

impl IncomingRpcDispatch for ClusterEngine {
    async fn append_entries(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        check_clock_skew(payload);
        let req: AppendEntriesRequest<HearthRaftConfig> =
            serde_json::from_slice(payload).map_err(|e| e.to_string())?;
        let resp = raft.append_entries(req).await.map_err(|e| e.to_string())?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }

    async fn vote(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: VoteRequest<u64> =
            serde_json::from_slice(payload).map_err(|e| e.to_string())?;
        let resp = raft.vote(req).await.map_err(|e| e.to_string())?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }

    async fn install_snapshot(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let raft = self.raft.as_ref().ok_or("Raft not initialised")?;
        let req: InstallSnapshotRequest<HearthRaftConfig> =
            serde_json::from_slice(payload).map_err(|e| e.to_string())?;
        let resp = raft
            .install_snapshot(req)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::to_vec(&resp).map_err(|e| e.to_string())
    }
}

// ── Background lag monitor ────────────────────────────────────────────────────

async fn run_lag_monitor(
    raft: openraft::Raft<HearthRaftConfig>,
    reads_allowed: Arc<AtomicBool>,
    threshold_ms: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(50));
    loop {
        interval.tick().await;
        let metrics = raft.metrics().borrow().clone();
        let lag = compute_lag_ms(&metrics);
        let ok = lag <= threshold_ms;
        reads_allowed.store(ok, Ordering::Relaxed);
        if !ok {
            warn!(
                lag_ms = lag,
                threshold_ms,
                "replication lag exceeds threshold — follower reads disabled"
            );
        }
    }
}

/// Estimate replication lag in milliseconds from Raft metrics.
///
/// Compares `last_log_index` (entries received) against `last_applied.index`
/// (entries applied to the state machine), using 5 ms per pending entry as a
/// conservative estimate.
pub(crate) fn compute_lag_ms(metrics: &RaftMetrics<u64, HearthNode>) -> u64 {
    let log_idx = metrics.last_log_index.unwrap_or(0);
    let applied_idx = metrics.last_applied.as_ref().map(|l| l.index).unwrap_or(0);
    if log_idx > applied_idx {
        (log_idx - applied_idx).saturating_mul(5)
    } else {
        0
    }
}

// ── Clock-skew check (§16.4) ──────────────────────────────────────────────────

/// Inspect an `AppendEntries` payload for embedded leader timestamps and warn
/// if the clock skew between this node and the leader exceeds 1 second.
///
/// NTP synchronisation is a deployment prerequisite for cluster mode.
fn check_clock_skew(payload: &[u8]) {
    let Ok(req) =
        serde_json::from_slice::<AppendEntriesRequest<HearthRaftConfig>>(payload)
    else {
        return;
    };
    for entry in &req.entries {
        let leader_ts = match &entry.payload {
            EntryPayload::Normal(cmd) => match cmd {
                RaftCommand::Put { leader_timestamp, .. }
                | RaftCommand::Delete { leader_timestamp, .. }
                | RaftCommand::Batch { leader_timestamp, .. } => *leader_timestamp,
            },
            _ => continue,
        };
        if leader_ts == 0 {
            continue;
        }
        let now_micros = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        let skew_ms = (now_micros - leader_ts).unsigned_abs() / 1_000;
        if skew_ms > 1_000 {
            warn!(
                skew_ms,
                "clock skew with leader exceeds 1 s — ensure NTP is configured"
            );
        }
        break;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::{CommittedLeaderId, LogId, ServerState, StoredMembership, Vote};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::storage::{EmbeddedStorageEngine, StorageConfig};

    fn make_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn open_engine(dir: &std::path::Path) -> Arc<EmbeddedStorageEngine> {
        let config = StorageConfig::dev(dir.to_path_buf());
        Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"))
    }

    fn make_metrics(log_idx: Option<u64>, applied_idx: Option<u64>) -> RaftMetrics<u64, HearthNode> {
        let make_log_id = |idx: u64| {
            Some(LogId::new(CommittedLeaderId::new(1, 0), idx))
        };

        RaftMetrics {
            running_state: Ok(()),
            id: 1,
            current_term: 1,
            vote: Vote::new(1, 1),
            last_log_index: log_idx,
            last_applied: applied_idx.and_then(|i| make_log_id(i)),
            snapshot: None,
            purged: None,
            state: ServerState::Follower,
            current_leader: None,
            millis_since_quorum_ack: None,
            membership_config: Arc::new(StoredMembership::default()),
            replication: None,
        }
    }

    // ── Single-node passthrough ───────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"k", b"v").await.expect("put");
        let got = engine.get(&realm, b"k").await.expect("get");
        assert_eq!(got, Some(b"v".to_vec()));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_delete_removes_value() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"k", b"v").await.expect("put");
        engine.delete(&realm, b"k").await.expect("delete");
        assert!(engine.get(&realm, b"k").await.expect("get").is_none());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_put_batch_writes_all() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        let pairs = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
        ];
        engine.put_batch(&realm, &pairs).await.expect("put_batch");
        assert_eq!(
            engine.get(&realm, b"a").await.expect("get a"),
            Some(b"1".to_vec())
        );
        assert_eq!(
            engine.get(&realm, b"b").await.expect("get b"),
            Some(b"2".to_vec())
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_scan_returns_entries() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        let realm = make_realm();
        engine.put(&realm, b"a", b"1").await.expect("put a");
        engine.put(&realm, b"b", b"2").await.expect("put b");
        let results = engine.scan(&realm, b"a", &[0xFF; 4]).await.expect("scan");
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn single_node_reads_ok_always_true() {
        let dir = tempdir().unwrap();
        let engine = ClusterEngine::single_node(open_engine(dir.path().join("data").as_path()));
        assert!(engine.reads_ok(), "single-node never blocks reads");
    }

    // ── compute_lag_ms ────────────────────────────────────────────────────────

    #[test]
    fn lag_zero_when_caught_up() {
        let m = make_metrics(Some(7), Some(7));
        assert_eq!(compute_lag_ms(&m), 0);
    }

    #[test]
    fn lag_zero_when_no_log() {
        let m = make_metrics(None, None);
        assert_eq!(compute_lag_ms(&m), 0);
    }

    #[test]
    fn lag_proportional_to_pending_entries() {
        let m = make_metrics(Some(20), Some(10));
        assert_eq!(compute_lag_ms(&m), 50); // 10 entries × 5 ms
    }

    #[test]
    fn lag_zero_when_applied_ahead_of_log() {
        // Shouldn't happen in practice but must not underflow.
        let m = make_metrics(Some(5), Some(10));
        assert_eq!(compute_lag_ms(&m), 0);
    }

    // ── leader_timestamp_now ──────────────────────────────────────────────────

    #[test]
    fn leader_timestamp_is_positive_and_recent() {
        let ts = ClusterEngine::leader_timestamp_now();
        assert!(ts > 0);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as i64;
        assert!((now - ts).abs() < 1_000_000, "timestamp within 1 second");
    }

    // ── Clock-skew check ──────────────────────────────────────────────────────

    #[test]
    fn check_clock_skew_does_not_panic_on_garbage_payload() {
        check_clock_skew(b"not json");
        check_clock_skew(b"{}");
        check_clock_skew(b"");
    }
}
