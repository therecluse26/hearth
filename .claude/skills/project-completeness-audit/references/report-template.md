# Report Template

Use this exact structure when writing the analysis file. Fill in the bracketed sections; keep the headings as-is so the output is consistent across audits.

```markdown
# Completeness Analysis — <project name>
_Generated: <date> · Spec source: <path> · Code rev: <git sha if available>_

## Summary
- Total requirements: N
- Complete: N (%) · Partial: N · Missing: N · Divergent: N · Unverifiable: N
- Top risks: <bulleted, 3–5 items>

## Requirements Matrix
| ID | Requirement | Priority | Status | Evidence | Notes |
|----|-------------|----------|--------|----------|-------|

## Findings by Area
### <Area 1>
Per-requirement detail: what spec says, what was found, gap.

## Spec Issues
Ambiguities, contradictions, untestable requirements.

## Out-of-Spec Implementations
Things in the code/UI not traceable to any requirement.

## Resolution Todo List
Ordered by priority, then dependency order. Use GitHub-style checkboxes.

- [ ] **[P0][M]** Implement <thing> — resolves `REQ-003`, `REQ-007` · _depends on: none_
- [ ] **[P0][S]** Add validation for <thing> — resolves `REQ-012` · _depends on: above_
- [ ] **[P1][L]** Refactor <thing> to match spec — resolves `REQ-019` (divergent)
- [ ] **[P1][S]** Clarify with stakeholder: <ambiguity> — resolves spec issue #2
- [ ] **[P2][S]** Add test coverage for <thing> — resolves `REQ-005` (untested)

## Recommended Next Steps
Short narrative summary of where to start and why, referencing the todo list above.
```