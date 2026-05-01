---
name: project-completeness-audit
description: Audit a project's completeness against its specification by exploring both the codebase and the running UI, cross-referencing findings, and producing a gap analysis with a resolution todo list. Use this skill whenever the user asks to check what's left to build, compare a project against its specs/requirements, identify gaps between specification and implementation, audit feature completeness, or determine "is this done yet" — even if they don't use the word "audit". Also use when the user mentions spec files, requirements docs, or a PRD alongside a codebase and wants to know what's missing or divergent.
---

# Project Completeness Audit

Audit this project's completeness against its specification. Investigate both the codebase and the running UI, cross-reference findings against spec files, and produce a gap analysis report saved as a markdown file.

## Arguments

The skill accepts three optional positional arguments when invoked:

- `$1` — **output path** for the report (default: `./completeness-analysis.md`)
- `$2` — **feature scope**: a single feature, area, or subsystem to audit instead of the whole project (e.g., `"authentication"`, `"realm admin UI"`, `"src/rbac/"`). When provided, restrict spec ingestion, code exploration, and UI walkthrough to requirements and code that fall under that scope. Out-of-scope requirements are excluded from the matrix entirely (not marked missing). State the active scope at the top of the report.
- `$3` — **spec path(s)**: file or directory containing the requirements (e.g., `./docs/specs/`, `./PRD.md`, or a comma-separated list). Recommended — providing this skips the spec-discovery prompt. If omitted, search likely locations (`specs/`, `docs/specs/`, `docs/`, `requirements/`, `README.md`, root-level `*.md`) and confirm the candidates with the user before proceeding.

If any argument is omitted, fall back to the default behavior. If `$2` is provided but ambiguous (e.g., `"auth"` could mean authentication or authorization), confirm with the user before proceeding.

## Inputs to confirm

Beyond the arguments above, confirm these with the user (ask only for what isn't obvious from context):

- **Codebase root** — defaults to current working directory
- **UI access** — a URL if the app is already running, or a launch command (e.g., `npm run dev`). If there's no UI, skip the UI exploration phase.

## Method

### 1. Ingest specs

Recursively read every file under the spec path. If a feature scope (`$2`) was provided, only extract requirements that fall within that scope — judge based on the requirement's subject, not just keyword match (e.g., a "rate limit on login" requirement belongs to authentication scope even if "auth" doesn't appear in the sentence).

Extract each distinct requirement with:

- Stable ID (`REQ-001`, …)
- Source file + section
- Type: `functional` | `non-functional` | `ui` | `data` | `integration` | `security` | `performance`
- Priority if stated (`must` / `should` / `could`)
- Acceptance criteria if present

Flag ambiguities and contradictions between spec files instead of silently resolving them — the user needs to know about these.

### 2. Explore the code

- Map the project structure (entry points, modules, routes, data models, services, tests).
- For each requirement, search for corresponding implementation. Record concrete evidence as `path/to/file.ext:line` references.
- Note implementations that exist but don't match the spec (partial, divergent, or stubbed).
- Check tests: which requirements have test coverage, which don't.

### 3. Explore the UI

Skip this phase if the project has no UI.

- Launch or navigate to the UI.
- Walk through every user-facing flow implied by the spec.
- For each UI requirement, capture: present / partial / missing / broken, plus a one-line observation.
- Note UI elements present in the app but not in the spec (scope creep candidates).

### 4. Cross-reference

For every requirement, assign exactly one status:

- ✅ **Complete** — implemented in code, visible in UI (where applicable), behavior matches spec
- 🟡 **Partial** — present but missing acceptance criteria, edge cases, or polish
- 🔴 **Missing** — no implementation found
- ⚠️ **Divergent** — implemented differently than spec
- ❓ **Unverifiable** — cannot determine from code/UI alone (state the reason)

### 5. Build a resolution todo list

From every non-✅ requirement and every spec issue, derive a concrete, actionable todo. Each todo must:

- Reference the requirement ID(s) or spec issue it resolves
- State the action in imperative form ("Implement X", "Add test for Y", "Clarify Z with stakeholder")
- Include effort estimate: `S` (<1d) / `M` (1–3d) / `L` (>3d)
- Include priority: `P0` (blocker) / `P1` (should-fix) / `P2` (nice-to-have)
- List dependencies on other todos where applicable

## Rules

These keep the audit honest:

- Every status claim cites evidence: file paths, line numbers, UI routes, or "no matches found for X". Naming alone is not evidence — verify behavior.
- If a spec requirement is ambiguous, record both interpretations rather than picking one.
- Distinguish "not found" from "searched and absent" — say which.
- Don't infer ✅ from the presence of a related file; only assign it when behavior is verified.

## Output

Write the report to the output path using the template in `references/report-template.md`. Then print the absolute path of the saved file so the user can open it.