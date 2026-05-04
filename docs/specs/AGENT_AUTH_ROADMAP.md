# Agent Authentication & Authorization — Implementation Roadmap

_Companion to [AGENT_AUTH.md](./AGENT_AUTH.md). Drafted 2026-05-04 in response to REQ-083→089 in [`docs/gaps/completeness_analysis.md`](../gaps/completeness_analysis.md)._

## Purpose

[AGENT_AUTH.md](./AGENT_AUTH.md) specifies the agent identity & authorization model. This roadmap sequences its delivery, anchors the Admin UI surface (REQ-083→089) to its prerequisite work, and explains why those audit items are deferred from the current Admin UI cleanup branch.

The implementation order in [AGENT_AUTH.md § 14](./AGENT_AUTH.md#14-implementation-phases) is the source of truth. This document does not redefine it — it links UI deliverables to their backend dependencies and surfaces the resulting blockers.

---

## Phase Summary

| Phase | Theme | UI deliverables | Backend deliverables |
|-------|-------|-----------------|----------------------|
| **A** | Foundation | none | `AgentId` newtype, agent CRUD, credentials, Agent Card, DPoP proof + token issuance, REST endpoints |
| **B** | MCP & Delegation | none | Protected resources, Resource Indicators, Token Exchange, OBO, consent, delegation chain enforcement |
| **C** | Permissions & Approval | **C.6 Approval admin UI** | Tool permission grammar, evaluation, scope intersection, approval lifecycle, webhooks |
| **D** | Advanced (AATs, A2A, CAEP) | **D.8 Delegation chain visualization** | AAT issuance, agent discovery, transaction tokens, cross-realm trust, CAEP signals, workload identity |

Phase A → B → C → D is a strict ordering per [AGENT_AUTH.md § 14](./AGENT_AUTH.md#14-implementation-phases). UI cannot ship before its backend predecessors.

---

## Mapping the Admin UI Audit (REQ-083→089) to Phases

| Audit ID | Audit description | Depends on | Earliest phase |
|----------|------------------|-----------|----------------|
| REQ-083 | Service-account / agents list page | A.2 (agent CRUD) | A |
| REQ-084 | Agent create form | A.2 | A |
| REQ-085 | Agent status transitions (Suspend/Resume/Revoke) | A.2 | A |
| REQ-086 | Agent credential management (API key + asymmetric, one-time reveal) | A.3 (agent credentials) | A |
| REQ-087 | User-to-agent consent management view | B.6 (consent management) | B |
| REQ-088 | Approval-requests management page | C.4 (approval lifecycle) | C |
| REQ-089 | Delegation chain visualization | B.7 (delegation enforcement), D.8 | D |

**Implication:** REQ-083→089 cannot land as a single change-set. Each row gates on its own phase. Building any one of them requires the corresponding backend phase to be complete and tested.

---

## Current Backend Status (verified 2026-05-04)

| Component | Status | Evidence |
|-----------|--------|----------|
| `AgentId` newtype | Absent | No reference in `src/core/types.rs` |
| Agent entity, CRUD | Absent | No `Agent` type in `src/identity/`; no `AgentEngine` trait |
| Agent credentials | Absent | No `agt:cred:*` storage keys in `src/identity/keys.rs` |
| DPoP proof / token | Absent | No DPoP module in `src/identity/` |
| Token Exchange (RFC 8693) | Absent | No `urn:ietf:params:oauth:grant-type:token-exchange` handler in `src/protocol/web/oauth.rs` |
| Consent (user-to-agent) | Absent (OAuth client consent only) | `ConsentRecord` in `src/identity/types.rs` is OAuth scope consent — no agent semantics |
| Delegation chain enforcement | Absent | No `act` claim handling in token issuance |
| Approval request lifecycle | Absent | No `approval` module; no `appreq:*` keys |

Building Phase A → C is genuinely greenfield work. Estimated scope (per `AGENT_AUTH.md § 14` test matrix):

- **Phase A:** ~7 features × multiple test layers ≈ 3–4 weeks
- **Phase B:** ~7 features ≈ 3–4 weeks
- **Phase C:** ~6 features ≈ 2–3 weeks
- **Total before C.6 (admin UI) is buildable:** ~8–11 weeks of backend work plus its own ~1 week of UI work.

---

## Why REQ-083→089 Are Deferred From The Admin UI Cleanup Branch

The `feature/authz-migration` branch closes the post-RBAC-migration Admin UI completeness gap. Its scope is **wiring & polishing existing backend capabilities through the Admin UI**, not building new identity primitives.

Building UI shells without backend creates three concrete failure modes:

1. **Operator confusion.** A working "Create agent" form that POSTs to a 501 endpoint is worse than a missing menu item. Operators report bugs against incomplete code paths.
2. **Test rot.** Smoke tests covering empty-state UIs become baseline expectations; they're hard to retire when real backend lands.
3. **Spec drift.** Templates committed in advance of the backend lock in field names and shapes that conflict with the spec evolution that always accompanies a new feature.

Per the [VISION.md](../vision/VISION.md) discipline of "no half-finished implementations," REQ-083→089 are flipped to `✅ N/A — roadmap-tracked` in the gap doc. They are not absent work; they are correctly-sequenced future work tracked here.

---

## Triggering Phase A

This branch does **not** start Phase A. The trigger is a separate planning conversation — e.g., a customer commitment, a design partner needing agent identity, or scheduling Phase A as the next sprint after the current Phase 2 Organizations close-out.

When Phase A is started:

1. Start a feature branch (`feature/agent-identity`) off `main`.
2. Follow [AGENT_AUTH.md § 14](./AGENT_AUTH.md#14-implementation-phases) step order strictly: A.1 → A.2 → ... → A.7. Do not skip ahead.
3. For each step, write tests first per [TESTING.md](./TESTING.md) and [CLAUDE.md § TDD](../../CLAUDE.md#tdd-workflow-mandatory).
4. Phase A ends when every step has unit + integration coverage and passes `cargo nextest run --workspace` + `cargo clippy --all-targets -- -D warnings`.
5. Open the Admin UI work for REQ-083→086 only after A.2 + A.3 are merged and stable on `main`.

---

## See Also

- [AGENT_AUTH.md](./AGENT_AUTH.md) — normative spec
- [AUTHORIZATION.md](./AUTHORIZATION.md) — RBAC model the agent permissions extend
- [ARCHITECTURE.md § 12.1](./ARCHITECTURE.md#121-newtype-ids) — newtype ID conventions for `AgentId`
- [TESTING.md](./TESTING.md) — eight testing layers
- [`docs/gaps/completeness_analysis.md`](../gaps/completeness_analysis.md) — REQ-083→089 entries flipped to `✅ N/A — roadmap-tracked`
