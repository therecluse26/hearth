//! Hot tier auto-sizing: detect available system memory via `/proc/meminfo`
//! or cgroup v1/v2 limits, reserve margin, and convert bytes to hot tier
//! entry count.

/// Conservative per-entry estimate: average key + value + `HotEntry` +
/// `HashMap` overhead. This load-bearing constant is used to convert a
/// memory budget into a hot tier entry count.
const ESTIMATED_BYTES_PER_HOT_ENTRY: usize = 1024;

/// Floor capacity. Even when memory detection yields 0, the hot tier must
/// have room for at least the active working set.
const MIN_HOT_TIER_CAPACITY: usize = 1_000;

/// Minimum margin floor in bytes (2 GiB).
const MARGIN_FLOOR_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Threshold in bytes above which cgroup v1 limits are treated as
/// "unlimited" (sentinel values from container runtimes).
const CGROUP_V1_UNLIMITED_THRESHOLD: usize = 100 * 1024 * 1024 * 1024 * 1024;

/// Detects available system memory in bytes.
///
/// Precedence: `/proc/meminfo` → cgroup v2 (`memory.max`) →
/// cgroup v1 (`memory.limit_in_bytes`).
///
/// Returns `None` when detection fails — caller falls back to
/// [`MIN_HOT_TIER_CAPACITY`].
pub(crate) fn detect_available_memory() -> Option<usize> {
    // 1. /proc/meminfo — MemAvailable (preferred)
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(bytes) = parse_meminfo_available(&contents) {
            return Some(bytes);
        }
    }

    // 2. cgroup v2 — memory.max
    if let Ok(contents) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        if let Some(bytes) = parse_cgroup_v2_max(&contents) {
            return Some(bytes);
        }
    }

    // 3. cgroup v1 — memory.limit_in_bytes
    if let Ok(contents) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
        if let Some(bytes) = parse_cgroup_v1_limit(&contents) {
            // Validate: cgroup v1 returns a sentinel (≥ 100 TiB) when
            // no limit is set. Cross-check against MemTotal to detect this.
            let total_mem = std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|m| parse_meminfo_total(&m));
            if let Some(total) = total_mem {
                if bytes < total {
                    return Some(bytes);
                }
            } else if bytes < 256 * 1024 * 1024 * 1024 * 1024 {
                // Fallback: no MemTotal available, guard with 256 TiB cap.
                return Some(bytes);
            }
        }
    }

    None
}

/// Computes hot tier capacity from available system memory or an explicit
/// memory budget override.
///
/// Reserves margin (`max(20%, 2 GiB)`) and converts bytes to entries
/// using [`ESTIMATED_BYTES_PER_HOT_ENTRY`].
///
/// When `override_max_memory` is `Some`, uses that as the budget instead
/// of detecting from the system. A budget of 0 always yields
/// [`MIN_HOT_TIER_CAPACITY`].
pub fn auto_size_hot_tier_capacity(override_max_memory: Option<usize>) -> usize {
    let budget = match override_max_memory {
        Some(b) => b,
        None => detect_available_memory().unwrap_or(0),
    };

    if budget == 0 {
        return MIN_HOT_TIER_CAPACITY;
    }

    let margin = (budget * 20 / 100).max(MARGIN_FLOOR_BYTES);
    let hot_bytes = budget.saturating_sub(margin);

    if hot_bytes == 0 {
        return MIN_HOT_TIER_CAPACITY;
    }

    (hot_bytes / ESTIMATED_BYTES_PER_HOT_ENTRY).max(MIN_HOT_TIER_CAPACITY)
}

// ── Parsers ──────────────────────────────────────────────────────────

/// Parses `MemAvailable` from `/proc/meminfo` contents. Values are in kB.
pub(crate) fn parse_meminfo_available(contents: &str) -> Option<usize> {
    for line in contents.lines() {
        if line.starts_with("MemAvailable:") {
            let kb = line.split_whitespace().nth(1)?.parse::<usize>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Parses `MemTotal` from `/proc/meminfo` contents (used for cgroup v1
/// sentinel cross-check).
pub(crate) fn parse_meminfo_total(contents: &str) -> Option<usize> {
    for line in contents.lines() {
        if line.starts_with("MemTotal:") {
            let kb = line.split_whitespace().nth(1)?.parse::<usize>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Parses cgroup v1 `memory.limit_in_bytes`.
///
/// Returns `None` for sentinel values ≥ 100 TiB (common Docker/container
/// patterns where no limit is set).
pub(crate) fn parse_cgroup_v1_limit(contents: &str) -> Option<usize> {
    let limit = contents.trim().parse::<usize>().ok()?;
    if limit >= CGROUP_V1_UNLIMITED_THRESHOLD {
        None
    } else {
        Some(limit)
    }
}

/// Parses cgroup v2 `memory.max`.
///
/// Returns `None` when the value is the string `"max"` (no limit).
pub(crate) fn parse_cgroup_v2_max(contents: &str) -> Option<usize> {
    let trimmed = contents.trim();
    if trimmed == "max" {
        return None;
    }
    trimmed.parse::<usize>().ok()
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_meminfo_available ───────────────────────────────────

    #[test]
    fn parse_meminfo_realistic() {
        let contents = "MemTotal:       16384000 kB\nMemFree:         2048000 kB\nMemAvailable:    12288000 kB\n";
        assert_eq!(parse_meminfo_available(contents), Some(12_582_912_000));
    }

    #[test]
    fn parse_meminfo_no_available_line() {
        let contents = "MemTotal:       16384000 kB\nMemFree:         2048000 kB\n";
        assert_eq!(parse_meminfo_available(contents), None);
    }

    #[test]
    fn parse_meminfo_empty() {
        assert_eq!(parse_meminfo_available(""), None);
    }

    // ── parse_meminfo_total ───────────────────────────────────────

    #[test]
    fn parse_meminfo_total_present() {
        let contents = "MemTotal:       16384000 kB\nMemAvailable:    12288000 kB\n";
        assert_eq!(parse_meminfo_total(contents), Some(16_777_216_000));
    }

    #[test]
    fn parse_meminfo_total_absent() {
        assert_eq!(parse_meminfo_total("MemAvailable:    12288000 kB\n"), None);
    }

    // ── parse_cgroup_v1_limit ─────────────────────────────────────

    #[test]
    fn parse_cgroup_v1_limited() {
        assert_eq!(parse_cgroup_v1_limit("4294967296\n"), Some(4_294_967_296));
    }

    #[test]
    fn parse_cgroup_v1_limited_with_newline() {
        assert_eq!(parse_cgroup_v1_limit("4294967296\n\n"), Some(4_294_967_296));
    }

    #[test]
    fn parse_cgroup_v1_unlimited_near_max() {
        // 9223372036854771712 ≈ 8 EiB — the classic cgroup v1 sentinel
        assert_eq!(
            parse_cgroup_v1_limit("9223372036854771712\n"),
            None,
            "8 EiB sentinel should be treated as unlimited"
        );
    }

    #[test]
    fn parse_cgroup_v1_unlimited_threshold() {
        let threshold: usize = 100 * 1024 * 1024 * 1024 * 1024; // 100 TiB
        assert_eq!(parse_cgroup_v1_limit(&format!("{threshold}\n")), None);
    }

    #[test]
    fn parse_cgroup_v1_under_threshold() {
        let under: usize = 99 * 1024 * 1024 * 1024 * 1024; // 99 TiB
        assert_eq!(parse_cgroup_v1_limit(&format!("{under}\n")), Some(under));
    }

    // ── parse_cgroup_v2_max ───────────────────────────────────────

    #[test]
    fn parse_cgroup_v2_limited() {
        assert_eq!(parse_cgroup_v2_max("8589934592\n"), Some(8_589_934_592));
    }

    #[test]
    fn parse_cgroup_v2_max_string_unlimited() {
        assert_eq!(parse_cgroup_v2_max("max\n"), None);
    }

    #[test]
    fn parse_cgroup_v2_max_string_unlimited_no_newline() {
        assert_eq!(parse_cgroup_v2_max("max"), None);
    }

    #[test]
    fn parse_cgroup_v2_garbage() {
        assert_eq!(parse_cgroup_v2_max("not-a-number\n"), None);
    }

    #[test]
    fn parse_cgroup_v2_empty() {
        assert_eq!(parse_cgroup_v2_max(""), None);
    }

    // ── auto_size_hot_tier_capacity (arithmetic) ──────────────────

    #[test]
    fn zero_budget_returns_floor() {
        assert_eq!(auto_size_hot_tier_capacity(Some(0)), 1_000);
    }

    #[test]
    fn tiny_budget_below_margin_returns_floor() {
        // 1 GiB: margin = 2 GiB, hot = 0 → floor
        let budget = 1024 * 1024 * 1024; // 1 GiB
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 1_000);
    }

    #[test]
    fn three_gib_budget() {
        // 3 GiB: margin = max(614 MiB, 2 GiB) = 2 GiB, hot = 1 GiB → 1_048_576
        let budget = 3 * 1024 * 1024 * 1024;
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 1_048_576);
    }

    #[test]
    fn four_gib_budget() {
        // 4 GiB = 4_294_967_296
        // margin = max(858_993_459, 2_147_483_648) = 2_147_483_648
        // hot = 2_147_483_648 → 2_097_152 entries
        let budget = 4 * 1024 * 1024 * 1024;
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 2_097_152);
    }

    #[test]
    fn thirty_two_gib_budget() {
        // 32 GiB = 34_359_738_368
        // margin = max(6_871_947_673, 2_147_483_648) = 6_871_947_673
        // hot = 27_487_790_695 → 27_487_790_695 / 1024 = 26_843_545
        let budget = 34_359_738_368usize;
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 26_843_545);
    }

    #[test]
    fn ten_gib_budget_margin_is_percentage() {
        // 10 GiB = 10_737_418_240
        // margin = max(2_147_483_648, 2_147_483_648) = 2_147_483_648
        // hot = 8_589_934_592 → 8_388_608 entries
        let budget = 10 * 1024 * 1024 * 1024;
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 8_388_608);
    }

    #[test]
    fn exactly_margin_floor() {
        // 2 GiB: margin = max(429_496_729, 2_147_483_648) = 2_147_483_648
        // hot = 0 → floor
        let budget = MARGIN_FLOOR_BYTES;
        assert_eq!(auto_size_hot_tier_capacity(Some(budget)), 1_000);
    }
}
