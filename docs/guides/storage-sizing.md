# Storage Sizing Guide

This guide covers working-set sizing assumptions for Hearth's embedded storage
engine and provides capacity planning guidance for datasets that exceed available
RAM — including the common single-node scenario where the dataset is 10× or more
the size of physical memory.

## Storage layer architecture

Hearth layers three tiers that serve reads in order:

```
Read path: hot tier → memtable → SST files
                ↑ lock-free   ↑ in-memory   ↑ mmap'd on disk
```

| Tier | Implementation | Medium | Typical p50 | Typical p99 |
|------|---------------|--------|-------------|-------------|
| Hot tier | `HashMap` + `ArcSwap` | DRAM | < 5 µs | < 10 µs |
| Memtable | `BTreeMap` + read lock | DRAM | < 20 µs | < 100 µs |
| SST files | `memmap2` read-only mmap | page cache / NVMe | < 100 µs | < 500 µs |

These ranges match the CI gate thresholds in `benches/storage_gate.rs` and
`benches/demotion_latency.rs`. Run `make bench-gate` on your target hardware
to collect authoritative numbers.

## Hot tier memory model

The hot tier stores entries in a `HashMap<CompositeKey, HotEntry>` wrapped in
`ArcSwap`. Each entry consists of:

- **Key**: `RealmId` (16 bytes UUID) + key bytes (variable; typically 16–64 bytes for UUIDs or email strings)
- **Value**: `Vec<u8>` heap allocation (serialised entity; typically 200–500 bytes for sessions/users)
- **Reference bit**: one `AtomicBool` (1 byte, but aligned to 1 byte in the struct)
- **`HashMap` node overhead**: ~48 bytes (pointer + hash + control byte with Robin Hood probing)

**Conservative accounting used by `auto_size.rs`:** 1 024 bytes per entry.

**Realistic average for identity workloads:** 400–600 bytes per entry
(assuming 64-byte keys and 300-byte session payloads).

### Automatic capacity sizing

On startup, `auto_size::auto_size_hot_tier_capacity()` queries available memory
in order:

1. `/proc/meminfo` → `MemAvailable` (Linux)
2. Cgroup v2 → `memory.max` minus `memory.current`
3. Cgroup v1 → `memory.limit_in_bytes` minus `memory.usage_in_bytes`

It then reserves `max(20%, 2 GiB)` as an OS/application margin and divides the
remainder by 1 024 bytes to produce the hot tier capacity, subject to a floor of
1 000 entries.

**Formula:**

```
available = MemAvailable (bytes)
margin    = max(available × 0.20, 2 GiB)
budget    = available − margin
capacity  = max(budget / 1024, 1000)
```

**Example — 8 GiB RAM, 6 GiB available:**

```
margin   = max(6 GiB × 0.20, 2 GiB) = 2 GiB
budget   = 6 GiB − 2 GiB = 4 GiB
capacity = 4 GiB / 1024 ≈ 4 194 304 entries
```

On an 8 GiB node Hearth can hold ~4 M hot entries. At a realistic 500 bytes/entry
this consumes ~2 GiB of RSS, leaving the reserved 2 GiB for the OS page cache
that backs cold SST reads.

You can override auto-sizing by setting `hot_tier_capacity` explicitly in
`hearth.yaml`:

```yaml
storage:
  hot_tier_capacity: 500000   # explicit override; 0 = auto-size
```

## Working-set vs dataset size

### Datasets that fit in hot tier

When the active working set fits within hot tier capacity, all reads are
lock-free `ArcSwap` loads and p99 stays under 10 µs. This is the design target
for a single-realm deployment with ≤ 1 M active sessions on a node with ≥ 4 GiB RAM.

### Datasets that exceed hot tier but fit in RAM

Entries evicted from the hot tier via the clock-sweep algorithm fall through to
the memtable (a `BTreeMap` protected by a read lock). The memtable is bounded by
`memtable_flush_threshold_bytes` (default 64 MiB); entries beyond that threshold
are flushed to SST files.

At this scale, p99 climbs to 50–200 µs depending on memtable size and lock
contention.

### Datasets ≥ 10× RAM (single node)

When the on-disk dataset is an order of magnitude larger than physical RAM, the
OS page cache becomes the primary performance lever. SST files are mapped with
`memmap2` using `MAP_SHARED | MAP_POPULATE` and served by the kernel page cache.

**Memory-mapping assumptions:**

- SST files are mapped read-only at engine open time. The OS pages in blocks on
  demand; the first read to a cold block incurs a page fault (1–5 ms on NVMe
  SSD, 50–200 µs on optane/PCIe 5.0).
- After the first access, the block lives in the page cache until evicted by
  memory pressure (`vm.swappiness`, `vfs_cache_pressure`).
- Hearth does not pin pages or call `madvise(MADV_WILLNEED)` — the OS LRU
  determines what stays hot.

**Expected degradation curve:**

| Hot-tier hit rate | Median p50 | p99 |
|-------------------|-----------|-----|
| > 90% (typical warm-up) | < 5 µs | < 10 µs |
| 70–90% | < 20 µs | < 100 µs |
| 50–70% | < 50 µs | < 500 µs |
| < 50% (working set >> hot tier) | < 100 µs | 1–5 ms |

These figures assume NVMe storage. Spinning disk will shift p99 by 1–2 orders
of magnitude on cold-page faults.

### Single-node sizing reference (10× dataset)

The table below gives conservative RAM recommendations for operating a single
Hearth node where the total on-disk dataset is approximately 10× physical RAM.
"Active sessions" refers to sessions accessed at least once in the past hour.

| Total users | Active sessions | Recommended RAM | Expected hot-tier entries | p99 read (warm) |
|-------------|-----------------|-----------------|--------------------------|-----------------|
| 100 K | 10 K | 1 GiB | 750 K (auto) → all fit | < 10 µs |
| 1 M | 100 K | 4 GiB | 3 M (auto) → all fit | < 10 µs |
| 10 M | 500 K | 8 GiB | 6 M (auto) → 500 K active ≈ 8% of hot | < 50 µs |
| 100 M | 2 M | 32 GiB | 25 M (auto) → 2 M active ≈ 8% of hot | < 200 µs |
| 1 B | 10 M | 128 GiB | 100 M (auto) → 10 M active ≈ 10% of hot | < 500 µs |

> **Note**: "active sessions" at 10% of total users is a common identity-server
> workload profile. Skewed access distributions (Zipf) will outperform these
> estimates; uniform random access will approach the worst-case column.

## Tuning checklist for large datasets

1. **Let auto-sizing run first.** The `auto_size` heuristic is calibrated for
   identity workloads. Override only after measuring with `make bench-gate`.

2. **Reserve page cache headroom.** On Linux, `vm.swappiness=10` and
   `vm.vfs_cache_pressure=50` reduce page cache eviction under memory pressure,
   keeping cold SST blocks warm longer.

3. **Pin hot-tier to huge pages (advanced).** For deployments with > 10 M hot
   entries, huge-page backing for the `HashMap` allocation reduces TLB pressure.
   This requires `madvise(MADV_HUGEPAGE)` patched into `HotTier::new`; file a
   feature request if needed.

4. **Monitor hot-tier hit rate.** Hearth exposes `storage_hot_tier_hits` and
   `storage_hot_tier_misses` Prometheus counters. A miss rate above 30% suggests
   the hot-tier capacity is undersized for the active working set.

5. **Run the demotion benchmark.** `PROTOC=protoc cargo bench --bench demotion_latency`
   measures pre/post-demotion p99 on your hardware and validates the 500 µs
   ceiling from `docs/guides/storage-sizing.md`.

## Benchmark data reference

All latency claims in this guide are derived from the CI gate assertions in:

- `benches/storage_gate.rs` — absolute p50/p99 thresholds for hot-tier, session,
  and user lookup paths
- `benches/demotion_latency.rs` — three-phase demotion cycle p99 assertion
  (`demotion_cycle/pre_demotion_read`, `demotion_cycle/post_demotion_read`)
- `benches/tiered_storage.rs` — Criterion throughput benchmarks for hot/cold
  promotion and memory footprint

Run on your target hardware:

```sh
# Absolute threshold gates (fails CI if thresholds are exceeded)
make bench-gate

# Full Criterion suite with HTML reports
PROTOC=protoc cargo bench

# Individual demotion scenario
PROTOC=protoc cargo bench --bench demotion_latency

# Compare against a saved main baseline (regression detection)
PROTOC=protoc cargo bench --bench storage_gate -- --baseline main
bash scripts/check-bench-regression.sh 5
```

HTML reports are written to `target/criterion/` after a full bench run.
