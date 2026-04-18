# Hearth: The Identity Database

### A Purpose-Built, Open-Source Database for Identity and Authorization

---

## 1. Executive Summary

Every application needs authentication and authorization. No application wants to build it.

The current landscape forces teams into a miserable choice: pay a SaaS vendor $50K–$500K per year for a black box you don't control, or self-host a JVM behemoth that requires a dedicated team to keep running. Neither option is acceptable for the growing number of teams that need auth to be fast, reliable, self-hosted, and operationally simple.

**Hearth is a purpose-built identity database.** It is not another auth server bolted onto Postgres. It is a single-binary, memory-safe, high-performance database designed from first principles for identity workloads: storing users, managing sessions, validating tokens, enforcing permissions, and federating identity across protocols. It ships as one binary. It runs on one port. It stores its own data. It clusters and self-heals without external coordination. It targets sub-millisecond p99 latency on the hot path — the same class of performance you expect from Redis, because auth is on the critical path of every request.

The strategic insight is simple: **auth is a database problem masquerading as an application problem.** Keycloak, Ory, Auth0, and every other solution in this space are applications layered on top of generic databases. They inherit all the operational complexity of those databases (backups, replication, connection pooling, schema migrations) and add their own complexity on top. A purpose-built identity database collapses this entire stack into a single, optimized system — the same way TigerBeetle collapsed the "application + Postgres" ledger stack into a purpose-built ledger database, and the same way ClickHouse collapsed the "application + generic RDBMS" analytics stack.

Hearth is AGPL-3.0 licensed (with commercial licensing available), written in a memory-safe systems language (Rust), and designed to be the last piece of auth infrastructure a team ever installs.

---

## 2. The Problem

### 2.1 The Operational Tax of Self-Hosted Auth

Ask any platform team what their auth infrastructure looks like and you'll get a description that sounds like a Rube Goldberg machine:

- **Keycloak** (or Ory Hydra, or some homegrown OAuth server) running on 2–4 JVM instances behind a load balancer
- **Postgres** (or MySQL) as the backing store, with its own HA setup, backup schedule, and connection pooling via PgBouncer or pgcat
- **Redis** (or Memcached) as a session store and token cache, because Keycloak is too slow to hit on every request
- A **sidecar or middleware layer** that validates JWTs, caches JWKS keys, and short-circuits auth checks to avoid round-tripping to Keycloak
- A **separate authorization service** (Open Policy Agent, Cerbos, or homegrown RBAC) because Keycloak's authorization model is inadequate for anything beyond basic roles
- **Custom glue code** connecting all of the above: token refresh logic, session synchronization, logout propagation, and the inevitable edge cases where the caching layers disagree with the source of truth

This is the "auth stack" — a distributed system that nobody planned, nobody wants to maintain, and nobody fully understands. It evolved organically because no single product does the job well enough to stand alone.

The operational burden is staggering. A mid-stage startup with a platform team of 5 engineers routinely dedicates 0.5–1.0 FTE to keeping auth infrastructure running. Not improving it. Not building features. Just keeping it from falling over. At a fully-loaded engineering cost of $250K–$400K per year, that's real money being burned on what should be a solved problem.

### 2.2 The Performance Problem Nobody Talks About

Auth is on the hot path. Every API request, every page load, every WebSocket connection touches auth. And yet the dominant self-hosted solutions treat performance as an afterthought:

- **Keycloak's token endpoint** typically delivers 5–20ms p50 latencies, with p99 regularly exceeding 100ms. Under load, GC pauses push tail latencies into the hundreds of milliseconds. This is why every serious Keycloak deployment has Redis in front of it.
- **Ory Hydra** is better (Go, no JVM), but it still round-trips to Postgres for every token introspection. At scale, you're bottlenecked on your database's connection limits and query latency.
- **Auth0's free and low tiers** impose hard rate limits (often cited around 300 requests/second) that teams hit surprisingly quickly. Even paid tiers add 10–50ms of network latency per auth call to an external service.

The industry has accepted these numbers as normal. They are not normal. They are an artifact of building auth as an application on top of a generic database. A purpose-built system that stores identity data in optimized in-memory structures, with a write-ahead log for durability, should deliver **sub-millisecond p99 for token validation and session lookup** — the same performance class as Redis, because the data structures and access patterns are similar in complexity.

The performance gap matters because it drives architectural complexity. Teams build caching layers, sidecars, and short-circuit logic specifically to avoid hitting their auth system. Remove the performance problem and you remove the caching layer, the sidecar, the consistency bugs that arise when caches disagree with the source of truth, and the operational burden of running all that infrastructure.

### 2.3 The Cost Problem

SaaS auth pricing is designed to scale with your success — which is a polite way of saying it's designed to extract maximum revenue as you grow.

- **Auth0** charges per monthly active user, with pricing that becomes punitive at scale. A B2B SaaS with 100K MAU on Auth0's professional tier is paying north of $50K/year, and enterprise features (SSO, SCIM, MFA policies) push that significantly higher.
- **Clerk** offers better DX but similar pricing dynamics. The developer experience is excellent until the invoice arrives.
- **WorkOS** charges per SSO connection, which sounds reasonable until you have 200 enterprise customers each requiring their own identity provider integration.
- **Cognito** is cheap until you need anything beyond basic username/password, at which point you discover that AWS's idea of "identity management" was designed by someone who has never shipped a B2B product.

These prices are not unreasonable given the difficulty of the problem and the quality of the services. But they represent a structural tax on every SaaS company, and they create a dependency on vendors who can (and do) change pricing, deprecate features, and impose architectural constraints. The existence of viable self-hosted alternatives should put downward pressure on these prices — but the current self-hosted options are so painful that most teams pay the SaaS tax rather than endure the operational suffering.

### 2.4 The Fragmentation Problem

The auth ecosystem is fragmented in a way that compounds every other problem:

- **Authentication** is one service (Keycloak, Auth0, your OAuth server)
- **Authorization** is a different service (OPA, Cerbos, Authzed, homegrown RBAC)
- **Session management** is often a third system (Redis, with custom logic)
- **User management** is sometimes in the auth server, sometimes in your application database, often partially in both
- **Multi-tenancy** is almost always custom code, because the auth server's concept of "organizations" doesn't match your product's concept of "tenants"

Each of these systems has its own data model, its own operational requirements, its own failure modes, and its own upgrade path. They communicate over the network, introducing latency, partial failure scenarios, and consistency challenges. And they were never designed to work together — the integration is always custom, always fragile, and always the platform team's problem.

This fragmentation is not because the domain is inherently complex. It's because no product has been ambitious enough to integrate all these concerns into a single, coherent system. Hearth is that product.

---

## 3. The Opportunity

### 3.1 Why Now?

The purpose-built identity database was not feasible five years ago. Several converging trends make it newly possible:

**Rust has matured.** The Rust ecosystem has crossed the threshold from "interesting experiment" to "proven production infrastructure language." TigerBeetle (Zig), DuckDB (C++), and Turso/libSQL (Rust/C) have demonstrated that small teams can build production-grade databases in modern systems languages. The Rust async ecosystem (tokio), cryptography libraries (ring, rustls, RustCrypto), and serialization frameworks are now battle-tested. Five years ago, building a database in Rust meant fighting the language and its ecosystem. Today, it means leveraging them.

**The TigerBeetle precedent.** TigerBeetle proved that the "purpose-built database for a specific domain" thesis works — not just technically, but as a product and a business. They identified that financial ledgers were being badly served by generic databases, built a purpose-built alternative with extreme performance characteristics, and created a new category. The identity domain has the same structural characteristics: high frequency access patterns, strict consistency requirements, well-defined data model, and an existing ecosystem of generic tools doing the job poorly.

**Zanzibar-style authorization has become the standard.** Google's Zanzibar paper (2019) and its open-source descendants (SpiceDB, OpenFGA) have established relationship-based access control as the right model for fine-grained permissions. But these systems run as separate services, requiring another piece of infrastructure to deploy and another network hop on every request. Embedding Zanzibar-style authorization directly into the identity database eliminates this overhead entirely.

**Passkeys and WebAuthn are reaching critical mass.** The industry is finally, genuinely moving beyond passwords. Apple, Google, and Microsoft have shipped passkey support in their platforms. But implementing passkeys requires tight integration between the auth system and the credential store — exactly the kind of integration that's awkward when auth is an application layer and credentials are in a separate database.

**The "modern data stack" collapse.** The industry is experiencing a correction against over-distributed architectures. Teams that adopted microservices and SaaS-for-everything are consolidating back toward simpler, more integrated systems. SQLite is resurgent. Single-binary tools are ascendant. The market appetite for "one binary that does the whole job" has never been higher.

**S3-compatible object storage is everywhere.** Cheap, durable, universally available object storage changes the calculus for database backup and snapshot strategies. A purpose-built database can use local SSDs for hot data and S3 for snapshots and cold replicas, achieving durability guarantees that previously required complex replication setups.

### 3.2 The Market

The identity and access management market is valued in the tens of billions annually and growing at 12–15% CAGR. More importantly, it's a market where no product has achieved the kind of dominant, beloved-by-developers position that Stripe holds in payments or Twilio held in communications. The closest is Auth0, which is respected but not loved, and which has stagnated since its acquisition by Okta.

The developer auth segment specifically — the tools developers choose when building new applications — is in active flux. Clerk and WorkOS have demonstrated that there's appetite for better DX, but they're SaaS-only. On the self-hosted side, Keycloak is the default by inertia, not by merit. Zitadel is the most promising challenger but is written in Go (limiting performance ceiling), depends on external Postgres/CockroachDB, and has adopted BSL licensing. The gap between "what developers want" and "what exists" is wide.

---

## 4. Strategic Positioning

### 4.1 Hearth Is a Database, Not an Auth Server

This distinction is the single most important strategic decision in the project, and it's worth being explicit about why.

When you say "auth server," people think: Keycloak, Auth0, a web application that handles login flows. They evaluate you on UI polish, provider integrations, and how many OAuth providers you support out of the box. You're competing in a crowded market on feature checklists.

When you say "identity database," people think: TigerBeetle, ClickHouse, Redis. They evaluate you on performance, reliability, operational simplicity, and architectural elegance. You're competing in a market where purpose-built solutions are rare and differentiation is massive.

More fundamentally, the "database" framing is *accurate*. The core of every auth system is a data management problem:

- **Storing users, credentials, and profiles** — this is a data storage problem with specific consistency and encryption requirements
- **Managing sessions** — this is a time-series-like data problem with high write throughput and TTL-based expiration
- **Validating tokens** — this is a lookup problem that should be as fast as a key-value read
- **Evaluating permissions** — this is a graph traversal problem (Zanzibar-style relationship checks) that benefits enormously from in-memory data structures
- **Federating identity** — this is a protocol translation problem layered on top of the data layer

Everything else — the OAuth flows, the SAML endpoints, the SCIM provisioning — is protocol surface on top of a data engine. Existing products are built as applications that delegate data management to a generic database. Hearth inverts this: it's a database that exposes protocol-native interfaces.

### 4.2 The Competitive Landscape

| Product | Type | Runtime | Storage | License | Self-Hosted | Key Limitation |
|---------|------|---------|---------|---------|-------------|----------------|
| **Keycloak** | Auth server | JVM | External (Postgres, MySQL) | Apache 2.0 | Yes | Operational complexity, performance |
| **Auth0** | SaaS platform | N/A | Managed | Proprietary | No | Cost at scale, vendor lock-in |
| **Clerk** | SaaS platform | N/A | Managed | Proprietary | No | Cost at scale, no self-host |
| **WorkOS** | SaaS platform | N/A | Managed | Proprietary | No | Enterprise-only focus, per-connection pricing |
| **Ory** | Auth toolkit | Go | External (Postgres, MySQL, CockroachDB) | Apache 2.0 | Yes | Split across multiple binaries, complexity |
| **Zitadel** | Auth server | Go | External (Postgres, CockroachDB) | Apache 2.0 / BSL | Yes | Go performance ceiling, external DB dependency, license concerns |
| **Supabase Auth** | Auth module | Go/Elixir | Postgres (Supabase-managed) | Apache 2.0 | Partial | Tightly coupled to Supabase ecosystem |
| **Authzed/SpiceDB** | Authorization only | Go | External (various) | Apache 2.0 | Yes | Authorization only, no authn |
| **Hearth** | Identity database | Rust | **Embedded** | AGPL-3.0 / Commercial | **Yes** | New, unproven |

The critical differentiator is in the "Storage" column. Every competitor depends on an external database. Hearth *is* the database. This is not a minor architectural detail — it eliminates an entire class of operational problems (connection pooling, schema migrations, backup coordination, database version compatibility, HA configuration for the backing store) and enables performance characteristics that are physically impossible when you're round-tripping to Postgres.

### 4.3 The TigerBeetle Parallel

TigerBeetle's insight was that financial ledgers have specific invariants (double-entry accounting, strict serializability, no data loss ever) that generic databases can enforce only with significant application-level complexity. By building a database that understands ledger semantics natively, they achieved:

- **100x performance improvement** over application-on-Postgres
- **Operational simplicity** — single binary, no external dependencies
- **Correctness by construction** — the database enforces ledger invariants that the application layer had to enforce manually

Hearth applies the same logic to identity:

- Identity data has specific invariants (credential uniqueness, session consistency, permission transitivity) that generic databases enforce clumsily
- Identity access patterns are specific (high-frequency reads, infrequent writes, TTL-based expiration, graph traversal for permissions) and poorly served by generic query planners
- Identity operations have specific performance requirements (sub-millisecond hot path) that are achievable only with purpose-built data structures

The parallel is not cosmetic. It's structural.

---

## 5. Core Design Principles

### 5.1 Radical Operational Simplicity

**One binary. One port. One config file. Zero external dependencies.**

Installing Hearth should be: download a binary, run it, point your application at it. Not: provision a Postgres instance, configure connection strings, run schema migrations, set up a Redis cluster for session caching, deploy a sidecar for token validation, configure an authorization service, and hope the six moving pieces stay in sync.

The operational simplicity principle is non-negotiable and influences every design decision. If a feature requires an external dependency, we find a way to embed it or we don't ship the feature. If a configuration option requires expertise to set correctly, we pick a good default and don't expose the option. If a deployment model requires a human operator to coordinate multiple processes, we automate the coordination.

This principle is inspired by SQLite ("just works"), DuckDB (zero-config analytical queries), and TigerBeetle (single binary, deterministic execution). The common thread is that purpose-built databases can afford to be radically simpler than generic ones because they serve a narrower set of use cases and can make more assumptions about workload characteristics.

### 5.2 Performance Is Not Optional

Auth is on the critical path. Hearth treats latency the way a trading system treats latency: as a first-class design constraint, not a metric to be optimized after the fact.

Concretely:
- The hot path (token validation, session lookup, permission checks) runs entirely in memory, against purpose-built data structures, with no allocations in the steady state
- Writes go through a write-ahead log to durable storage; reads never block on writes
- The system is designed to saturate modern hardware: memory bandwidth, CPU caches, NVMe I/O
- The system distinguishes between hot data (in memory, sub-microsecond access) and cold data (on disk, millisecond-class access), automatically promoting records based on access patterns — enabling a single node to manage far more data than fits in RAM without sacrificing hot-path performance
- No garbage collection, no JVM warm-up, no interpretive overhead

This is not premature optimization. It's a design constraint that shapes the architecture from day one. You cannot bolt on sub-millisecond performance after building a system that round-trips to Postgres.

### 5.3 Opinionation as a Feature

Hearth makes decisions so you don't have to. The configuration surface is deliberately small. The number of supported authentication flows is deliberately limited to the ones that matter. The authorization model is a single Zanzibar-style engine that covers the full spectrum of access control — from simple roles to fine-grained relationships to conditional permissions — without bolting together separate RBAC, ABAC, and ReBAC systems.

What Hearth explicitly **does**:
- OIDC / OAuth 2.0 (authorization code, client credentials, device authorization)
- SAML 2.0 (SP-initiated and IdP-initiated)
- WebAuthn / Passkeys
- Magic links / passwordless email
- TOTP / authenticator apps
- SCIM 2.0 provisioning
- Zanzibar-style permissions: built-in RBAC schemas (admin/editor/viewer) as the starting point, fine-grained relationship-based permissions as the growth path, conditional rules for time-based and attribute-based policies
- Multi-tenancy with per-tenant identity provider configuration
- Session management with revocation and device tracking
- Comprehensive audit logging
- Password hashing with Argon2id default, support for bcrypt/PBKDF2/scrypt verification (for migration), automatic upgrade-on-login, and enforced minimum parameters

What Hearth explicitly **does not do**:
- LDAP server (legacy protocol; provide a migration path in, not ongoing support)
- RADIUS (not in scope; different domain)
- Custom authentication flow scripting (opinionated flows are the product)
- Generic policy engines or arbitrary scripting (not OPA/Rego; one permission model, not a framework for inventing your own)
- CMS or user-facing UI framework (provide headless APIs and reference UIs)

The authorization model deserves special attention. Most teams start with roles (RBAC) and eventually need something more expressive — per-document sharing, organization hierarchies, time-limited access. The industry's answer has been to bolt together separate systems: Casbin for RBAC, OPA for policy, SpiceDB for relationships. Hearth's answer is one engine with progressive complexity: roles are a built-in pattern expressed as relationships, fine-grained permissions emerge naturally from the same graph, and conditional relationships (caveats) handle attribute-based and time-based rules without a separate policy language. One model to learn, one system to operate, one set of audit logs to review.

The discipline of saying no is what makes the product coherent. Every "pluggable" and "configurable" decision point in Keycloak is a support burden, a documentation page, a potential misconfiguration, and a performance cost. Hearth trades flexibility for correctness and simplicity.

### 5.4 Correctness Over Cleverness

Identity infrastructure has zero tolerance for data loss and low tolerance for inconsistency. Hearth's design prioritizes:

- **Crash safety**: every committed write survives a power failure. The WAL is fsync'd before acknowledgment.
- **Consistency**: within a cluster, reads reflect the most recent committed write. No eventually-consistent session stores that lead to "phantom logout" bugs.
- **Auditability**: every mutation to identity data is logged in an append-only audit log. Compliance teams can reconstruct the state of any identity at any point in time.
- **Encryption at rest**: credentials and sensitive fields are encrypted with per-tenant keys. Compromising the storage layer does not compromise credentials.

### 5.5 Migration Is a First-Class Feature

Adopting new infrastructure is risky. Hearth de-risks adoption by treating migration as a core feature, not an afterthought:

- **Import tools** for Keycloak, Auth0, Clerk, Cognito, Firebase Auth, and Okta
- **Shadow mode**: run Hearth alongside your existing auth system, replaying traffic to validate correctness before cutover
- **Export tools**: Hearth never holds your data hostage. Full export to standard formats at any time.
- **Protocol compatibility**: standard OIDC/OAuth2/SAML endpoints that work with any client library, not proprietary APIs that create lock-in

---

## 6. Technical Architecture (High-Level)

### 6.1 Single-Binary Architecture

Hearth compiles to a single statically-linked binary. Inside that binary are several logically distinct subsystems:

```
┌─────────────────────────────────────────────────────────┐
│                     Hearth Binary                       │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Protocol    │  │   Protocol   │  │   Protocol   │  │
│  │  OIDC/OAuth2  │  │   SAML 2.0   │  │   SCIM 2.0   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │           │
│  ┌──────┴─────────────────┴─────────────────┴───────┐  │
│  │              Identity Engine (Core API)            │  │
│  │   authn · sessions · users · tenants · audit      │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                   │
│  ┌──────────────────┴───────────────────────────────┐  │
│  │           Authorization Engine (Zanzibar)         │  │
│  │    relationship tuples · check · expand · watch   │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                   │
│  ┌──────────────────┴───────────────────────────────┐  │
│  │              Storage Engine                       │  │
│  │   WAL · memtable · SSTs · indexes · encryption    │  │
│  └──────────────────┬───────────────────────────────┘  │
│                     │                                   │
│  ┌──────────────────┴───────────────────────────────┐  │
│  │          Cluster / Replication Layer              │  │
│  │   Raft consensus · auto-failover · snapshots      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Protocol Layer**: Speaks OIDC, OAuth 2.0, SAML 2.0, SCIM 2.0, and WebAuthn natively. Each protocol is implemented as a thin adapter over the Identity Engine. The protocol layer also exposes a gRPC and REST management API for operations that don't map to a standard protocol (tenant configuration, migration, admin operations).

**Identity Engine**: The core logic layer. Handles user lifecycle, credential management, session management, token issuance and validation, and multi-tenant isolation. This is where authentication flows are orchestrated and where the opinionated decisions about supported flows are enforced.

**Authorization Engine**: A Zanzibar-style permission system embedded directly in the same process, covering the full RBAC → ReBAC → conditional spectrum through a single engine. Key design choices:
- **Pre-built RBAC schemas**: Admin/editor/viewer role templates work out of the box. Teams start with familiar role-based patterns and grow into fine-grained relationships when they need them.
- **Conditional relationships (caveats)**: Tuples can carry conditions evaluated at check time — time-based expiration, IP range restrictions, attribute comparisons — following the pattern established by SpiceDB caveats. This provides ABAC-lite capability without a separate policy engine.
- **SDK-level RBAC convenience APIs**: The SDK exposes `assignRole()` / `hasRole()` / `removeRole()` helpers that abstract away the underlying tuple mechanics. Developers who only need roles never have to think about relationship graphs.
- **Co-located with identity data**: Because relationship tuples live in the same storage engine as users, tenants, and sessions, permission setup is atomic with identity operations. Creating a user and assigning their initial roles happens in a single transaction — no dual-write synchronization, no eventual consistency between an identity store and a separate authorization service.

Permission checks are in-process function calls, not network requests — enabling sub-microsecond authorization checks once the data is in memory.

**Storage Engine**: A purpose-built embedded storage engine optimized for identity access patterns. Not a generic LSM tree or B-tree — a hybrid that recognizes the distinct access patterns of different identity data types:
- **User profiles and credentials**: relatively static, read-heavy, indexed by multiple keys (email, username, external ID, tenant). Stored in a B-tree-like structure optimized for point lookups.
- **Sessions**: time-bounded, write-moderate, naturally ordered by creation time with TTL-based expiration. Stored in a time-partitioned structure that efficiently handles both lookups and bulk expiration.
- **Relationship tuples**: graph-structured, read-heavy with occasional writes, traversed for permission checks. Tuples may carry optional condition data (caveats) evaluated at check time. Stored in an adjacency-list structure optimized for the specific traversal patterns of Zanzibar `Check` and `Expand` operations.
- **Audit log**: append-only, write-heavy, rarely read except for compliance queries. Stored in a sequential log structure, compacted to S3-compatible object storage for long-term retention.

All data types except the audit log participate in a **hot/cold tiered storage model**. Recently accessed records are held in the hot tier (in-memory, memory-mapped structures) for sub-microsecond read access. Records that have not been accessed within the eviction window are demoted to the cold tier (on-disk SSTs) and transparently promoted back to the hot tier on next access. The hot tier is auto-sized based on available system memory, enabling a single node to manage far more total records than fit in RAM while maintaining sub-millisecond latency for the active working set. See Section 7.3.1 for capacity implications.

**Cluster Layer**: Raft-based consensus for multi-node deployments. Automatic leader election, log replication, and snapshot-based recovery. The cluster layer is designed to be invisible in single-node mode — no configuration, no port allocation, no ceremony. In cluster mode, it handles membership changes, node failure detection, and data rebalancing without manual intervention.

### 6.2 Embedded vs. Server Modes

Like SQLite and DuckDB, Hearth supports two deployment modes:

**Server mode** (primary): Hearth runs as a standalone server process, accepting connections over the network. This is the default for production deployments. The server manages its own storage, clustering, and protocol endpoints.

**Embedded mode** (library): Hearth is linked directly into the application process as a library (via C ABI or language-specific bindings). The application calls Hearth functions directly, with no network overhead. This mode is ideal for:
- Edge deployments where a separate server process is impractical
- Testing and development where operational simplicity is paramount
- Applications where sub-microsecond auth latency is critical
- CLI tools and single-process applications

Embedded mode uses the same storage engine and provides the same durability guarantees as server mode. The only difference is the absence of the network layer and the cluster layer.

### 6.3 Language Choice: Rust

Hearth is written in Rust. This is a deliberate choice, not a trend-following one. The reasoning:

**Why Rust over Go:**
- Go's garbage collector introduces unpredictable latency spikes that are fundamentally incompatible with sub-millisecond p99 targets. You can tune GC, but you can't eliminate it.
- Go's runtime has a memory overhead floor (~5–10MB) that matters for embedded mode and edge deployments.
- Rust's ownership model provides compile-time guarantees about memory safety and data race freedom that are especially valuable in a security-critical system handling credentials and tokens.
- The Rust database ecosystem (sled, rocksdb bindings, tokio, tower) is more mature for this specific use case than Go's.

**Why Rust over Zig:**
- Zig is a defensible choice (TigerBeetle chose it), but the ecosystem is less mature. Fewer production-quality cryptography libraries, fewer protocol implementations to build on, smaller hiring pool.
- Rust's trait system and type-level programming enable ergonomic, zero-cost abstractions for protocol handling that Zig's comptime is less suited for.
- The risk-adjusted choice for a new project in 2025 favors Rust's stability and ecosystem size.

**Why Rust over C/C++:**
- Memory safety. A database handling authentication credentials cannot afford use-after-free, buffer overflow, or data race vulnerabilities. Rust provides these guarantees at compile time with zero runtime cost.

### 6.4 Hot Path Design

The hot path — the code that executes on every authenticated request — is the most performance-critical part of the system. It's designed with the following constraints:

1. **Zero allocations**: all data structures used on the hot path are pre-allocated or arena-allocated. No heap allocation per request.
2. **No syscalls for hot reads**: hot-tier data (active sessions, frequently-accessed user records, relationship tuples) lives in memory-mapped structures. Hot-tier reads are pointer dereferences, not I/O operations. Cold-tier reads incur a disk I/O on first access; see Section 7.3.1.
3. **Lock-free reads**: read operations use epoch-based reclamation or read-copy-update patterns. Readers never block on writers.
4. **Batched writes**: mutations are batched and committed to the WAL in groups, amortizing the cost of fsync across multiple operations.
5. **CPU-cache-friendly layouts**: data structures are designed for sequential memory access patterns where possible, minimizing cache misses on the hot path.

The target is for a single Hearth node to handle token validation and session lookup workloads at the same order of magnitude as Redis handles `GET` operations — because the underlying operations (hash table lookup, memory read, return value) are fundamentally similar in complexity.

**Cold path fallback.** Not all reads hit the hot tier. When a request targets a record that has been evicted to the cold tier — for example, a user who has not logged in for months — the read falls through to the on-disk SST layer. This incurs a disk I/O penalty (see Section 7.3.1 for target latencies) but happens transparently: the record is loaded, served, and promoted to the hot tier in a single operation. The design goal is that the cold path is invisible to the caller — the API contract is the same, only the latency differs. Critically, cold-path reads do not degrade hot-path performance: the promotion I/O is asynchronous with respect to other readers, and hot-tier data structures are never locked or invalidated by a cold promotion.

---

## 7. Performance Targets

These are design targets, not guarantees. They represent the performance that a purpose-built identity database *should* achieve based on analysis of the underlying operations, hardware capabilities, and comparable systems (Redis, TigerBeetle, DuckDB). They will be validated by continuous benchmarking against real hardware from day one.

### 7.1 Latency Targets (Single Node)

| Operation | Target p50 | Target p99 | Cold-path first access | Comparable System |
|-----------|-----------|-----------|----------------------|-------------------|
| Token validation (JWT verify + session lookup) | < 50 μs | < 500 μs | < 5 ms | Redis GET: ~100 μs p99 |
| Session lookup by ID | < 10 μs | < 100 μs | N/A (sessions always hot while active) | Redis GET: ~100 μs p99 |
| Permission check (direct relationship) | < 20 μs | < 200 μs | < 5 ms | SpiceDB: ~1–5ms p99 |
| Permission check (3-hop graph traversal) | < 100 μs | < 1 ms | < 10 ms | SpiceDB: ~5–20ms p99 |
| User lookup by email/ID | < 50 μs | < 500 μs | < 5 ms | Postgres indexed lookup: ~1–5ms |
| Token issuance (full OAuth2 flow) | < 1 ms | < 5 ms | < 10 ms | Keycloak: 5–50ms p50 |
| User creation (with credential hashing) | < 50 ms | < 100 ms | N/A (write path) | Dominated by Argon2id cost |

### 7.2 Throughput Targets (Single Node, Modern Hardware)

| Workload | Target (ops/sec/core) | Total (16-core server) |
|----------|----------------------|------------------------|
| Token validation (read-heavy) | 200,000+ | 3,000,000+ |
| Mixed read/write (95/5 read/write) | 100,000+ | 1,500,000+ |
| Permission checks | 150,000+ | 2,000,000+ |
| Session creation | 50,000+ | 500,000+ |

### 7.3 Capacity Targets (Single Node)

| Metric | Target |
|--------|--------|
| Users per node (total managed) | 100M+ |
| Users in hot tier (default, auto-tuned) | Adapts to available memory |
| Active sessions per node | 10M+ |
| Relationship tuples per node | 1B+ |
| Memory footprint (idle, 1M hot users) | < 500 MB |
| Memory footprint (idle, 10M hot users) | < 8 GB |
| Memory footprint (idle, 100M hot users) | < 50 GB |
| Disk footprint (100M total users) | < 200 GB |
| Binary size | < 50 MB |
| Cold start to serving requests | < 2 seconds |
| Cold-to-hot promotion latency | < 5 ms |

#### 7.3.1 Tiered Storage: Hot and Cold Data

Identity workloads follow a heavy power-law distribution. A system managing 100M registered users may see 5M monthly active users and 500K–1M daily active users. The remaining 95%+ of records — inactive accounts, churned users, rarely-accessed service accounts — are stored but almost never read. Requiring all 100M records to live in RAM at all times is wasteful; requiring operators to provision 50GB+ of memory per node for a workload that realistically touches 1–5% of records in any given hour is operationally hostile.

Hearth addresses this with a two-tier storage model:

**Hot tier.** Recently accessed records live in memory-mapped, cache-line-aligned structures designed for sub-microsecond reads. This is the tier described in Section 6.4: zero allocations, no syscalls, lock-free reads. The hot tier holds the *working set* — the subset of data actively being accessed — not the entire dataset. For a system with 1M daily active users, the hot tier may hold ~1–2M user records, all active sessions, and the relationship tuples reachable from those users.

**Cold tier.** Records that have not been accessed within the eviction window are stored in on-disk sorted string tables (SSTs), fully durable and queryable. Cold-tier reads are not failures — they are normal, expected operations for low-frequency data. Target latencies: < 5 ms on NVMe storage, < 20 ms on spinning disk. The cold tier uses the same data format as the hot tier, so no deserialization or format conversion is needed on promotion — just a memory copy.

**Promotion on access.** When a request targets a cold record, the system loads it from disk, serves the response, and promotes the record to the hot tier in a single operation. Subsequent accesses hit the hot tier. This is analogous to a CPU cache hierarchy: the first access is slow, subsequent accesses are fast. The promotion is asynchronous with respect to other hot-tier readers — it does not lock or invalidate existing hot-tier data structures.

**Eviction policy.** The hot tier uses a clock-based LRU approximation to decide which records to demote. Clock-based eviction was chosen over strict LRU because strict LRU requires linked-list mutation on every access — violating the zero-allocation, lock-free read constraints of the hot path (Section 6.4). The clock algorithm uses a single "recently used" bit per record, swept periodically. This provides near-LRU eviction quality at O(1) per-access overhead. LFU (least-frequently-used) was considered but rejected: identity workloads are bursty (a user logs in, performs a burst of actions, then goes idle), and LFU is pathological for bursty access patterns — it would retain stale-but-historically-frequent records over recently-active ones.

**Auto-tuning (default).** By default, the hot tier auto-sizes based on available system memory. At startup, Hearth reads the available physical memory (or cgroup memory limit in containerized environments), reserves a margin for the OS and other processes (20% of total memory or 2 GB, whichever is larger), and allocates the remainder to the hot tier. The hot tier dynamically adjusts as the working set grows or shrinks — if a traffic spike brings more users online, the hot tier grows; if traffic subsides, eviction reclaims memory. Cgroup awareness is critical: without it, a container with a 4 GB memory limit would attempt to use the host's full memory and be OOM-killed.

**Manual override.** Operators who need explicit control can set `storage.hot_tier_max_memory: 4GB` or `storage.hot_tier_memory_fraction: 0.7` in the configuration YAML. These settings cap hot-tier memory usage at a fixed value or a fraction of available memory, respectively. When both are set, the lower bound wins.

**Why it matters.** Without tiering, managing 100M users requires ~50 GB of RAM per node — always, regardless of how many users are actually active. With tiering, RAM usage is proportional to *active* users: a deployment serving 1M daily active users from a 100M-user dataset needs roughly 1–2 GB for user records, plus memory for sessions, indexes, and relationship tuples — potentially 3–5 GB total. This is the difference between requiring a $500/month high-memory VM and running comfortably on a $50/month standard instance. For the self-hosted, operationally-simple deployment model that Hearth targets, this reduction in hardware requirements is not a nice-to-have — it is essential.

### 7.4 The "Redis Replacement" Pitch

Many teams currently use the following architecture:

```
App → Redis (session cache) → Keycloak → Postgres
         ↓ (cache miss)
    Keycloak → Postgres
```

Hearth replaces this entire chain:

```
App → Hearth
```

With comparable or better latency on the hot path (session lookups, token validation), there is no need for a caching layer. The cache *is* the database. Sessions live in memory-mapped structures with WAL-backed durability. You get Redis-class read performance with database-class durability, in a single system that also handles the authentication and authorization logic.

And unlike Redis, which evicts data permanently when memory is exhausted, Hearth's tiered storage model gracefully spills cold records to disk. No data is lost. No cache invalidation logic is needed. The system transparently manages the boundary between what lives in memory and what lives on disk, based on real access patterns and available resources.

---

## 8. Adoption Strategy

### 8.1 The Five-Minute On-Ramp

First impressions matter more than feature completeness. A developer evaluating Hearth should go from "never heard of it" to "running locally with a working login flow" in under five minutes:

```bash
# Install (single binary, no dependencies)
curl -fsSL https://hearth.dev/install | sh

# Start the server (in-memory mode for development)
hearth serve --dev

# Open the admin console
open http://localhost:9090

# Or: create a tenant and application programmatically
hearth tenant create --name "my-app"
hearth app create --tenant "my-app" --redirect-uri "http://localhost:3000/callback"
```

The `--dev` flag starts Hearth in an opinionated development mode: in-memory storage (no persistence), relaxed security policies (localhost-only, no TLS required), pre-configured test users, and hot-reload for configuration changes. This mode is explicitly not for production — it's for getting started in seconds.

### 8.2 SDK Strategy

SDKs are the primary interface between application developers and Hearth. They must be:

- **Idiomatic**: a Go SDK should feel like Go, not like a Java SDK ported to Go
- **Complete**: every SDK should support the full OIDC/OAuth2 flow, session management, and permission checks
- **Framework-integrated**: thin wrappers for popular frameworks (Next.js middleware, Express middleware, Django middleware, Rails concern, Spring Security adapter, Axum extractor) that handle the common case in < 10 lines of code

**Priority order for SDK development:**
1. **TypeScript/JavaScript** (Next.js, Express, Hono) — largest developer population, highest impact
2. **Go** — primary language for backend infrastructure, natural fit for the target audience
3. **Python** (Django, FastAPI) — massive ecosystem, growing in backend development
4. **Rust** — native language, important for credibility and embedded mode
5. **PHP** (Laravel) — massive web ecosystem, widespread hosting infrastructure
6. **Java/Kotlin** (Spring Boot) — enterprise adoption, Keycloak migration path
7. **C#/.NET** — enterprise adoption
8. **Ruby** (Rails) — smaller but passionate community
9. **Elixir/Phoenix** — smaller but influential community

### 8.3 Migration Paths

Migration is the highest-friction part of adopting new infrastructure. Hearth addresses this with purpose-built migration tooling for each major source:

**Keycloak migration:**
- Import realms, clients, users, roles, and groups from a Keycloak export
- Map Keycloak's realm model to Hearth's tenant model
- Preserve user credentials (password hashes) so users don't need to re-register
- Support a dual-running period where Hearth and Keycloak are both active, with Hearth validating tokens issued by either system

**Auth0 migration:**
- Import users, connections, and applications via the Auth0 Management API
- Map Auth0's tenant/application model to Hearth's equivalents
- Handle Auth0-specific credential formats and social connection configurations

**Clerk migration:**
- Import users and organizations via the Clerk API
- Map Clerk's organization model to Hearth's multi-tenancy model

**Generic migration:**
- SCIM 2.0-based bulk import for any system that supports SCIM export
- CSV/JSON import for custom user databases
- Shadow mode for validating Hearth against production traffic before cutover

### 8.4 Drop-In Protocol Compatibility

Hearth's OIDC, OAuth 2.0, SAML, and SCIM endpoints conform strictly to their respective RFCs and specifications. Any client library that speaks standard OIDC (e.g., `openid-client` in Node.js, `golang.org/x/oauth2` in Go) should work with Hearth without modification. This means teams can adopt Hearth server-side without changing their application's auth client code — just point the OIDC discovery URL at Hearth instead of Auth0/Keycloak.

---

## 9. Business Model and Sustainability

### 9.1 AGPL-3.0 + Commercial — Open Source with Teeth

Hearth is dual-licensed: **AGPL-3.0** for open-source use, with **commercial licenses** available for organizations that need different terms. Not "open core with the interesting features behind a paywall." Not "source-available with a time-delayed permissive license." The full product is open source, always.

This is a deliberate strategic choice informed by hard lessons from the infrastructure ecosystem. The reasoning:

1. **Trust is the product.** Auth infrastructure sits at the heart of every application's security model. Teams need to trust that the infrastructure will be available, maintained, and unencumbered. The AGPL ensures the source is always open — no bait-and-switch to a proprietary license is possible because the existing codebase remains AGPL-3.0 forever.

2. **The AGPL protects the commons.** The cautionary tales of Redis, Elasticsearch, and Terraform show what happens when cloud providers offer permissively-licensed infrastructure as a managed service without contributing back. The AGPL's network-use clause (Section 13) requires anyone offering Hearth as a service to release their modifications. This protects the project and its contributors without restricting self-hosting, modification, or redistribution.

3. **Commercial licensing enables enterprise adoption.** Organizations that cannot or prefer not to operate under AGPL terms can obtain a commercial license. This is the same model used by Grafana Labs (AGPLv3 + commercial), MinIO (AGPLv3 + commercial), and MongoDB (SSPL + commercial). It funds development while keeping the project fully open source.

4. **The precedent works.** Grafana, MinIO, and Neo4j demonstrate that AGPL + commercial dual-licensing sustains both vibrant open-source communities and durable businesses. The AGPL is not a barrier to adoption — it is a guarantee that the project stays open.

### 9.2 Revenue Model: Hearth Cloud

The monetization strategy is a fully-managed hosted offering — **Hearth Cloud** — that provides:

- **Managed clusters** with automated provisioning, scaling, backup, and upgrades
- **Global edge deployment** with latency-optimized routing
- **SOC 2, HIPAA, and ISO 27001 compliance** certifications (expensive for individual teams to achieve)
- **Enterprise support** with SLAs, dedicated channels, and incident response
- **Advanced observability** — dashboards, alerting, and audit log analysis
- **Multi-region replication** with configurable consistency policies

This is the same model used by Confluent (Kafka), Elastic (pre-license-change), ClickHouse Inc, Turso (libSQL), and TigerBeetle. The open-source project is the product; the hosted offering is the business. This model works when:

1. The software is genuinely complex to operate at scale (Hearth, in clustered multi-region mode, qualifies)
2. The hosted offering provides meaningful value beyond "we run it for you" (compliance, global edge, enterprise support)
3. The open-source project is good enough that self-hosting is viable, creating competitive pressure that keeps the hosted offering honest

### 9.3 What Hearth Cloud Is Not

Hearth Cloud is not an excuse to cripple the open-source version. The open-source Hearth is a complete, production-grade identity database. It includes clustering, replication, all protocol support, all authorization features, and all administrative capabilities. Hearth Cloud competes on operational convenience and enterprise requirements (compliance certifications, SLAs, support), not on feature gating.

### 9.4 Funding Path

The project will likely follow a staged funding approach:

1. **Bootstrap / grants phase**: Build the core database and reach a functional v0.1. Apply to infrastructure-focused grants (Sovereign Tech Fund, NLnet, GitHub Sponsors, Open Source Collective). Target audience: early adopter developers who will battle-test the system and contribute.

2. **Seed funding**: Once the project has a working single-node system with OIDC support and demonstrated performance characteristics, raise a seed round from infrastructure-focused investors. The TigerBeetle comparison is the pitch: "We're doing for identity what TigerBeetle did for ledgers."

3. **Series A**: With Hearth Cloud in beta and paying customers, raise a Series A to fund the go-to-market and enterprise sales motions.

This path is not the only option. The project could remain community-funded and community-governed indefinitely. The funding path is presented as an option, not a commitment — and the AGPL-3.0 license ensures that the project's openness is not contingent on any particular funding outcome.

---

## 10. Roadmap and Phasing

### Phase 0: Foundation (Prototype)

**Goal**: Prove that the "identity database" concept works — that a purpose-built storage engine for identity data can achieve the target performance characteristics.

- Core storage engine with WAL, memtable, and persistent storage
- User CRUD with credential storage (Argon2id default, multi-algorithm verification)
- Session management (create, lookup, revoke, TTL expiration)
- Basic OIDC provider (authorization code flow)
- JWT issuance and validation
- Single-node only, no clustering
- CLI management tool
- Benchmark suite demonstrating performance targets
- Embedded mode (library) API

**Exit criteria**: A developer can run Hearth, create users, authenticate via OIDC, manage sessions, and observe sub-millisecond p99 on the hot path. Benchmark results are published and reproducible.

### Phase 1: Production Single-Node (v0.x)

**Goal**: A system that a brave team could run in production for a real application.

- OAuth 2.0 complete (authorization code, client credentials, device authorization, refresh tokens)
- WebAuthn / Passkey support
- Magic link / passwordless email authentication
- TOTP / MFA support
- Multi-tenancy (tenant isolation, per-tenant configuration)
- Admin API (REST + gRPC)
- Admin web console
- Zanzibar-style authorization engine (Check, Expand, Write, Watch)
- Audit logging
- TLS termination
- TypeScript and Go SDKs
- Keycloak import tool
- Documentation site

**Exit criteria**: A small team can migrate from Keycloak to single-node Hearth and run it in production with confidence. Performance targets are met on representative hardware.

### Phase 2: Production Clustering (v1.0)

**Goal**: Multi-node deployment suitable for production use by teams with significant scale.

- Raft-based consensus and log replication
- Automatic leader election and failover
- Online membership changes (add/remove nodes without downtime)
- Snapshot-based recovery
- SAML 2.0 support (SP and IdP)
- SCIM 2.0 provisioning
- Auth0 and Clerk import tools
- Python, Rust, and Java SDKs
- Shadow mode for zero-downtime migration
- Prometheus metrics and OpenTelemetry tracing
- Helm chart and systemd service file
- Security audit by a reputable third-party firm

**Exit criteria**: A team can deploy a 3-node Hearth cluster, survive node failures without downtime, and migrate from Auth0 or Keycloak with zero user-facing impact. v1.0 is declared production-ready.

### Phase 3: Scale and Ecosystem (v2.0+)

**Goal**: Hearth becomes the default choice for self-hosted identity infrastructure.

- Hearth Cloud launch (managed offering)
- Multi-region replication with configurable consistency
- S3-compatible object storage for cold data and audit logs
- Advanced analytics and reporting on auth events
- Compliance certifications (SOC 2, HIPAA)
- Remaining SDKs (C#, Ruby, Elixir)
- Remaining import tools (Cognito, Firebase Auth, Okta)
- Plugin system for custom identity providers (constrained, not arbitrary scripting)
- Edge deployment mode (embedded Hearth at the CDN edge)
- Community ecosystem: third-party integrations, contributed SDKs, deployment guides

---

## 11. Risks and Honest Tradeoffs

### 11.1 Building a Database Is Hard

This is the most common and most valid objection. Building a production-grade database is a multi-year effort that requires deep expertise in storage engines, consensus protocols, crash recovery, and performance engineering. Most database projects fail or never reach production quality.

**Mitigation**: Hearth's scope is deliberately narrower than a general-purpose database. It doesn't need a SQL parser, a query optimizer, a general-purpose type system, or support for arbitrary schemas. The data model is fixed and known: users, sessions, credentials, relationship tuples, audit events. This dramatically reduces the surface area of the storage engine. The system is closer in complexity to a purpose-built key-value store with domain-specific indexes than to Postgres.

Additionally, the Rust ecosystem provides battle-tested building blocks: `tokio` for async I/O, `ring` and `rustls` for cryptography, `serde` for serialization. Hearth doesn't need to build everything from scratch.

### 11.2 The Zig/TigerBeetle Risk

TigerBeetle chose Zig partly because they wanted to build everything from scratch — their own I/O runtime, their own memory allocator, their own networking stack. This approach maximizes control but also maximizes the amount of code that needs to be written and maintained. Hearth's decision to use Rust and leverage existing crates is a deliberate departure from this approach, trading some control for faster time-to-market and a broader contributor base.

The risk is that Rust's ecosystem crates introduce bugs, performance regressions, or security vulnerabilities that Hearth can't control. This is a real risk, but it's the same risk that every Rust project accepts, and the Rust ecosystem's track record of security and quality is strong.

### 11.3 Competing With Well-Funded Incumbents

Auth0 (Okta), Clerk, and WorkOS have raised hundreds of millions in venture capital. They have large engineering teams, established sales channels, and brand recognition. Hearth is competing with them — indirectly, on the self-hosted side of the market, but competing nonetheless.

**Mitigation**: Hearth is not competing with Auth0 on Auth0's terms. Auth0 is a SaaS platform; Hearth is a self-hosted database. The customers are different (teams that want/need self-hosted vs. teams that prefer SaaS), and the competitive dynamics are different. Hearth's real competition is Keycloak — and Keycloak's weaknesses are structural, not resource-dependent. No amount of JVM tuning will make Keycloak competitive on performance with a purpose-built Rust database. No amount of configuration options will make a multi-component deployment competitive on operational simplicity with a single binary.

### 11.4 The "Why Not Just Use Postgres" Objection

Sophisticated engineers will ask: "Why not just build a well-optimized auth layer on Postgres? Postgres is battle-tested, has built-in replication, and the auth-specific performance requirements could be met with proper indexing and connection pooling."

This is a reasonable objection, and the honest answer is: you *can* build a good auth system on Postgres. Ory and Zitadel do it. The question is whether "good" is sufficient, or whether "purpose-built" unlocks a categorically different level of performance and operational simplicity.

The argument for purpose-built:
- **Performance ceiling**: Postgres will always have overhead that a purpose-built system doesn't — query parsing, plan optimization, transaction management for a general-purpose transaction model, MVCC overhead. These costs are small individually but compound on a hot path that handles millions of requests per second.
- **Operational coupling**: depending on Postgres means inheriting Postgres's operational requirements — major version upgrades, vacuum tuning, connection pool management, replication configuration. These are well-understood but non-trivial.
- **Architecture constraints**: a Postgres-backed system cannot offer embedded mode, cannot achieve zero-allocation hot paths, and cannot co-locate the authorization graph with the session store in the same process without significant complexity.

The honest acknowledgment: if you already have a well-operated Postgres cluster and your auth performance requirements are modest (< 10K requests/second), building on Postgres is a reasonable choice. Hearth's value proposition is strongest for teams that need higher performance, want simpler operations, or are starting from scratch.

### 11.5 Adoption Risk

Infrastructure projects live or die by adoption. A technically superior product with no users is a hobby project. The identity database category doesn't exist yet — Hearth has to create it and convince people it's a category worth caring about.

**Mitigation**: This is the risk that the TigerBeetle framing partially addresses. TigerBeetle proved that "purpose-built database for X" is a viable category creation strategy. The migration tooling, drop-in protocol compatibility, and five-minute on-ramp are designed to minimize adoption friction. The AGPL-3.0 license keeps the source fully open, and commercial licensing ensures adoption is not gated by license incompatibility for enterprises that need it.

### 11.6 Single-Person / Small-Team Risk

If Hearth starts as a solo or small-team project, there is an inherent risk of key-person dependency. The project's bus factor is low until it reaches a critical mass of contributors.

**Mitigation**: Clear documentation, conventional Rust project structure, comprehensive test suites, and a contributor-friendly development process. The choice of Rust (large, growing community) over Zig (smaller community) partially mitigates this risk. Early focus on attracting contributors through good developer experience, clear contribution guidelines, and responsive maintainership.

### 11.7 The Scope Trap

The scope of this project is ambitious. Identity, authentication, authorization, multi-tenancy, clustering, migration, SDKs — the temptation to build everything at once is strong, and the risk of spreading too thin is real.

**Mitigation**: The phased roadmap is designed to manage scope aggressively. Phase 0 is deliberately minimal — a storage engine, OIDC, and sessions. Each subsequent phase adds functionality based on demonstrated demand, not speculative feature completeness. The principle is: do fewer things, but do them at a level of quality that establishes credibility.

---

## 12. What Success Looks Like

### Year 1–2: Proof of Concept

Hearth is a working, single-node identity database used in production by a small number of early-adopter teams. It has published, reproducible benchmarks showing order-of-magnitude performance improvements over Keycloak. It has a small but engaged community of contributors. The "identity database" framing has entered the vocabulary of infrastructure-aware developers.

Concrete markers:
- v1.0 released with clustering support
- 50+ GitHub stars → 2,000+ stars (organic growth from technical merit)
- 5–10 teams running Hearth in production
- Conference talks at RustConf, KubeCon, or equivalent venues
- Favorable comparison reviews from independent infrastructure bloggers

### Year 3–5: Category Establishment

Hearth is the default recommendation when someone asks "what should I use for self-hosted auth?" on Hacker News, Reddit, or in engineering Slack communities. It has displaced Keycloak as the serious self-hosted option for new projects. Hearth Cloud is generating revenue.

Concrete markers:
- 10,000+ GitHub stars
- 100+ production deployments (self-reported or discovered)
- Hearth Cloud with paying customers and a clear path to sustainability
- "Identity database" recognized as a product category in analyst reports
- Third-party ecosystem: community SDKs, deployment guides, integration plugins
- Security audit(s) completed with clean results

### Year 5–10: Infrastructure Standard

Hearth is to identity what Redis was to caching, what Kafka was to event streaming, what Postgres is to relational data: the obvious, default choice. "What identity database are you using?" is a normal question in architecture reviews.

Concrete markers:
- Hearth is included in "starter stack" recommendations alongside Postgres, Redis, and Kafka
- Major cloud providers offer managed Hearth (or Hearth Cloud has sufficient market position to make this unnecessary)
- The "auth stack" — the Rube Goldberg machine of Keycloak + Redis + OPA + glue code — is recognized as a legacy pattern
- Hearth's performance characteristics have made "auth caching layer" an unnecessary concept for most applications
- The project is financially sustainable through Hearth Cloud and/or foundation-style support

---

## Appendix: Open Questions and Areas for Further Exploration

The following items are not part of the core vision but represent areas where further thinking is needed:

1. **Authorization schema language approach**: The permission model needs a schema definition language — both SpiceDB and OpenFGA converged on this, and the developer experience benefits (validation, IDE support, version-controlled schemas) are clear. The open question is: how closely should Hearth follow SpiceDB's schema language (which is becoming a de facto standard) vs. designing a bespoke DSL optimized for Hearth's co-located architecture? SpiceDB compatibility would ease migration and leverage existing tooling; a custom language could better express Hearth-specific concepts like tenant-scoped relationships and identity-aware conditions.

2. **Expression language for conditions**: Conditional relationships (caveats) need an expression language for evaluating conditions at check time. CEL (Common Expression Language, used by Google and adopted by SpiceDB) is the obvious candidate — it's sandboxed, performant, and well-specified. The alternative is a custom expression evaluator that could be more tightly integrated with Hearth's type system and identity data model. The tradeoffs are ecosystem compatibility vs. integration depth and control over evaluation performance in the hot path.

3. **Event streaming / webhooks**: Should Hearth provide a built-in event system (user created, session revoked, permission changed) for downstream consumers? This is common in auth systems but adds scope. A webhook-based approach would be simpler than a full event streaming system.

4. **UI components**: Should the project maintain headless login/signup UI components (React, Vue, Svelte) as part of the core project, or leave this to the community? Clerk's strength is partly its pre-built UI components. There's a tension between "database, not application" positioning and the DX benefits of shipping UI components.

5. **Tenant federation**: For B2B SaaS use cases, should Hearth support a model where multiple Hearth instances federate identity across organizational boundaries? This is a complex feature but potentially high-value for large enterprise deployments.

6. **Hardware security module (HSM) integration**: For high-security deployments, should Hearth support PKCS#11 or cloud KMS integration for key management? This is common in enterprise auth products but adds significant complexity.

7. **Compliance-specific features**: Features like data residency (ensuring user data stays in a specific geographic region), right-to-be-forgotten (GDPR Article 17 compliance), and data classification may need to be part of the core product rather than addons. The scope implications are significant.

8. **Rate limiting and abuse prevention**: Should Hearth include built-in rate limiting, brute force protection, and bot detection, or should these be handled by a separate layer (WAF, API gateway)? The "single binary" principle argues for inclusion; the "do fewer things well" principle argues for exclusion.

---

*This document represents the foundational vision for the Hearth project. It is a living document, intended to evolve as the project matures, as assumptions are validated or invalidated, and as the competitive landscape shifts. The core thesis — that identity infrastructure deserves a purpose-built database, and that radical operational simplicity and extreme performance are achievable and valuable — is the stable foundation on which everything else is built.*
