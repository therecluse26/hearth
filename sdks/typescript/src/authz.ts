import type { HearthClient } from "./client.js";
import type { CapabilityBundle } from "./types.js";

/**
 * Cache key for a capability bundle: the page plus a stable hash of
 * its template-variable params. Changing any param produces a fresh key.
 */
function paramsKey(page: string, params: Record<string, string>): string {
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("&");
  return sorted ? `${page}?${sorted}` : page;
}

interface CachedEntry {
  bundle: CapabilityBundle;
  zookie: number;
}

/**
 * Caches capability bundles and threads the zookie through reads so the
 * user always sees their own writes.
 *
 * Flow:
 * 1. On every mutation that returns a zookie, the app calls
 *    `recordWrite(zookie)` — this raises the floor.
 * 2. On `capabilities(page, params)`, the cache passes
 *    `at_least_as_fresh_as = max(floor, cached.zookie)` to the server,
 *    ensuring stale replicas can't serve a response older than any
 *    write the user has already observed.
 * 3. `invalidate(page?)` drops cached bundles; subsequent reads refetch.
 *
 * The cache is deliberately in-memory and per-client — it's meant for
 * SPA page-scoped caching, not cross-tab or long-term storage.
 */
export class AuthzCache {
  private readonly client: HearthClient;
  private readonly accessToken: () => string;
  private entries = new Map<string, CachedEntry>();
  private floor = 0;

  constructor(client: HearthClient, accessToken: () => string) {
    this.client = client;
    this.accessToken = accessToken;
  }

  /**
   * Returns the capability bundle for a page. Hits the cache when the
   * cached zookie already satisfies the current floor; refetches otherwise.
   */
  async capabilities(
    page: string,
    params: Record<string, string> = {},
  ): Promise<CapabilityBundle> {
    const key = paramsKey(page, params);
    const cached = this.entries.get(key);
    if (cached && cached.zookie >= this.floor) {
      return cached.bundle;
    }
    const bundle = await this.client.capabilities(
      this.accessToken(),
      page,
      params,
    );
    const zookie = Math.max(bundle.token, this.floor);
    this.entries.set(key, { bundle, zookie });
    return bundle;
  }

  /**
   * Records a zookie returned from a mutation. Raises the cache floor
   * so subsequent `capabilities()` calls see at-least this version.
   */
  recordWrite(zookie: number): void {
    if (zookie > this.floor) {
      this.floor = zookie;
    }
  }

  /** Drops the cached bundle for a specific page, or all if omitted. */
  invalidate(page?: string): void {
    if (page === undefined) {
      this.entries.clear();
      return;
    }
    for (const key of Array.from(this.entries.keys())) {
      if (key === page || key.startsWith(`${page}?`)) {
        this.entries.delete(key);
      }
    }
  }

  /** Current monotonic floor — useful for diagnostics. */
  get currentFloor(): number {
    return this.floor;
  }
}
