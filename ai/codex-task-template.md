# Current Task Template

Use this template when starting a new Codex task.

This file defines how to write focused prompts for Codex in this repository.

## Standard task preamble

Before starting, read and follow:

- `/ai/agent-rules.md`
- `/ai/token-budget.md`
- `/ai/project-context.md`
- `/ai/current-status.md`

Treat these files as working contracts for this task.

Use minimal-diff mode.

Do not scan the whole repository unless the task explicitly requires it.

Run targeted tests first.

Run broad/full test suites only when:
- shared infrastructure changed,
- the task explicitly asks for it,
- or targeted tests are insufficient to verify the change.

Keep the final response concise.

## General task rules

Use one task per prompt.

Each task must be:
- focused,
- scoped,
- reviewable,
- testable where applicable.

Do not combine unrelated changes.

Do not make architectural decisions unless they are already documented or explicitly requested in the task.

If the requested implementation requires a new architecture decision, stop and report what decision is needed.

Do not change public APIs, repository structure, package behavior, or baseline meaning unless the task explicitly allows it.

---

## Implementation task template

Copy and fill this:

Task:
<describe one focused implementation task>

Scope:
- Work only on this task.
- Do not fix unrelated issues.
- Do not refactor unrelated code.
- Do not change public APIs unless required by this task.
- Do not update unrelated docs or baseline statuses.
- Do not add new hardening rules unless explicitly requested.

Expected change:
- <specific files/area if known>
- <expected behavior>
- <tests to add/update>

Out of scope:
- <explicit non-goals>
- <things Codex must not touch>

Verification:
- Run targeted tests first.
- Run full test suite only before final handoff or if shared infrastructure changed.
- Report commands and pass/fail counts only.

Output:
- changed files
- behavior changed
- tests run
- audit result if applicable
- short notes only

---

## Audit finding fix template

Copy and fill this:

Task:
Fix only this audit finding:

RuleId:
<RuleId>

Title:
<good title>

File:
<path if known>

Description:
<description>

Recommendation:
<recommendation>

Before changing code:
- Verify whether the finding is real or a false positive.
- Prefer focused tests or documentation fixes if runtime behavior is already correct.
- Do not fix other findings in this task.
- Do not add new hardening rules.

Scope:
- One finding only.
- Minimal diff.
- No new hardening rules.
- No broad refactor.
- No public API change unless required.
- No unrelated baseline updates.

Verification:
- Run targeted tests for the changed area.
- If available, rerun the relevant audit command.
- Remove generated audit reports.

Output:
- finding classification: real issue / false positive / unclear
- changed files
- behavior changed
- tests run
- audit result
- follow-up if needed

---

## Review-only task template

Copy and fill this:

Task:
Review the current implementation only.

Rules:
- Do not modify files.
- Do not create commits.
- Do not refactor.
- Do not run broad scans unless needed for this review.
- Focus only on the current diff/task.

Review focus:
- correctness
- scope control
- false positives / false negatives
- tests
- docs/baseline changes
- build/test result if run

Output format:

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

---

## Docs-only task template

Copy and fill this:

Task:
Update documentation only.

Scope:
- Do not change code.
- Do not change tests.
- Do not update baseline statuses unless explicitly requested.
- Do not rewrite unrelated sections.
- Keep the diff focused.

Expected change:
- <specific file>
- <specific section>
- <expected wording/meaning>

Verification:
- No build required unless documentation generation is part of the repository workflow.
- Review the rendered Markdown if formatting is relevant.

Output:
- changed files
- documentation changed
- verification performed
- short notes only

---

## Cleanup task template

Copy and fill this:

Task:
Perform only the requested cleanup.

Scope:
- Do not change behavior.
- Do not add rules.
- Do not refactor unrelated code.
- Do not update baseline statuses unless explicitly requested.
- Do not change public APIs.

Verification:
- Build only if code changed.
- Run tests only if cleanup could affect behavior.

Output:
- changed files
- cleanup performed
- verification performed
- short notes only

---

## Recommended workflow

Use one task per prompt.

Preferred order:

1. Implement focused change.
2. Run targeted tests.
3. Run full tests only if needed.
4. Review.
5. Apply minor fixes if review finds issues.
6. Commit.

Do not skip review for security, baseline, analyzer, or rule-behavior changes.