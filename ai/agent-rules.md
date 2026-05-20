# Agent Rules

These rules apply to Codex work in this repository.

## Role

Act as a focused implementation agent for this repository.

Your job is to:
- implement narrowly scoped changes,
- add or update focused tests for behavior-changing implementation work,
- preserve existing architecture,
- report concise results.

## Context rules

Use `/ai/token-budget.md` for context, scanning, test execution, and output limits.

Read additional `/ai/*.md` files only when the task references them or when needed for the current scope.

Do not scan the whole repository unless explicitly requested or approved after explaining the need.

## General rules

- Work only inside this repository.
- Do not modify external repositories.
- Do not add LLM/OpenAI/Azure OpenAI/Semantic Kernel/LangChain/MCP integrations.
- Do not add code generation or auto-fix features unless explicitly requested.
- Do not rename public APIs unless explicitly requested.
- Do not do broad refactors.
- Do not reformat unrelated files.
- Do not change unrelated baseline statuses.
- Do not commit generated audit reports.

## Task boundaries

Treat each task as one focused unit.

Do not combine:
- implementation and unrelated cleanup,
- review and implementation,
- hardening rule work and starter fix work,
- multiple audit findings in one change,
- new rules and fixes for existing findings.

If a task reveals a separate issue, report it as follow-up instead of fixing it immediately.

## Implementation style

Prefer:
- small deterministic changes,
- explicit heuristics,
- package-aware detection,
- focused tests,
- clear rule titles,
- heuristic wording in findings.

Avoid:
- over-engineering,
- generic repository-wide analyzers,
- broad regexes without tests,
- silently accepting weak evidence,
- hiding false positives through overly permissive detection.

## Finding fix mode

When fixing an audit finding:
- fix only the specified finding,
- verify whether it is a real issue or false positive before changing code,
- prefer tests or documentation fixes when runtime behavior is already correct,
- do not change public API unless required,
- do not add new hardening rules,
- do not fix unrelated findings in the same task,
- rerun only the relevant audit or targeted tests first.

## Testing rules

Every behavior-changing implementation should include focused tests.

For rule/detector work, add relevant:
- positive tests,
- negative tests,
- false-positive regression tests,
- package/sample/test exclusion tests when applicable.

Follow `/ai/token-budget.md` for test execution scope.

Do not run the full test suite by default.
Run the full test suite only when explicitly requested, before final handoff for implementation tasks, or when shared infrastructure changed.

## Audit report rules

Generated reports are runtime artifacts.

Do not commit:
- audit-report.md
- tmp-audit-starter.md
- tmp-audit-hardening.md
- reports generated during smoke tests

Remove temporary reports after smoke runs.

## Baseline rules

When implementing a new hardening rule:
- preserve existing RuleIds,
- add exactly one new RuleId unless requested otherwise,
- update `docs/security-baseline-v1.md`,
- mark baseline items as Implemented only for analyzer coverage,
- keep wording honest: static and heuristic,
- do not imply formal security compliance.

Do not update baseline docs for test-only, review-only, cleanup, or detector-fix tasks unless explicitly requested.

## Review mode

When the task says review-only:
- do not modify files,
- do not create commits,
- do not refactor,
- return findings only.

Use this output format:

```md
# Review

## Verdict
Ready to commit / Commit after minor fixes / Needs fixes before commit

## High-risk issues
None found / list issues

## Medium/low issues
None found / list issues

## False positive / false negative risks
None found / list risks

## Suggested fixes
None / list fixes

## Baseline/doc notes
None / list notes

## Test result
Not run / command and result
```

## Final response format

For implementation tasks, respond with:

```md
Done.

Changed:
- ...

Tests:
- ...

Audit:
- ...

Notes:
- ...
```

Keep the final response concise.