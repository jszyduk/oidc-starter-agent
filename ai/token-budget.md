# Token Budget Workflow

This repository uses Codex with a limited token/message budget.

## Primary goal

Use Codex for targeted implementation, focused review, and debugging.

Do not spend tokens on broad exploration unless explicitly requested.

## Default working mode

1. Read only the files needed for the current task.
2. Prefer targeted search over repository-wide scanning.
3. Make the smallest safe change.
4. Avoid unrelated refactors.
5. Avoid reformatting unrelated files.
6. Add or update focused tests for the changed behavior.
7. Run targeted tests first.
8. Do not run the full test suite by default.
9. Run the full test suite only:
   - before final handoff for implementation tasks,
   - when the change touches shared infrastructure,
   - or when explicitly requested.

## Repository scanning rules

Do not scan the whole repository by default.

Allowed:
- Search for exact rule IDs, class names, detector names, test names.
- Open nearby files directly related to the task.
- Inspect existing tests for the same detector/rule pattern.

Avoid unless requested:
- Reading all source files.
- Summarizing the whole repository.
- Refactoring unrelated detectors.
- Updating documentation outside the requested scope.

If broader analysis is required, explain why, list the files/areas to inspect, and wait for guidance before expanding scope.

Ask for guidance before:
- broad repository scans,
- unrelated module changes,
- public API changes,
- architectural decisions.

Reading a file does not imply permission to modify it.
Modify only files required by the current task.

## Test execution rules

Prefer this order:

1. Build when code changed or compile feedback is needed.
2. Run targeted tests for the changed rule/detector.
3. Do not run the full test suite by default.
4. Run the full test suite only when explicitly requested, before final handoff for implementation tasks, or when shared infrastructure changed.

If the user says they will run tests manually, do not run tests.
Provide the exact recommended test command instead.

For passing tests, report only:
- command
- passed/failed
- count

Do not paste long logs unless there is a failure.
For failures, paste only the relevant error excerpt.

## Documentation rules

Update docs, baseline mappings, or audit documentation only when the task explicitly includes documentation or rule mapping changes.

Do not update documentation opportunistically.

## Output rules

Keep final responses short.

Include:
- changed files
- behavior changed
- tests run
- audit result if applicable
- known limitations or follow-up only if important

Do not include:
- long explanations
- full diffs
- full logs
- repeated project context

## Stop conditions

Stop and ask for guidance if:
- the task requires a broad architectural decision,
- the fix requires public API changes,
- the task touches unrelated modules,
- test failures appear unrelated to the change,
- the audit finding may be a false positive rather than a code issue,
- the implementation requires broader scanning than the task allowed.

## Cost-saving reminders

- One finding = one focused task.
- One task = minimal diff.
- Do not “improve while here.”
- Do not add new rules during fix tasks.
- Do not run expensive commands repeatedly if the first result is enough.