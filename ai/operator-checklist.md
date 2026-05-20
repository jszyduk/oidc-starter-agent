# Operator Checklist

Use this checklist before and after running a Codex task.

This file is for the human operator, not for Codex automation.

## Before starting a Codex task

Check:

- [ ] Is this task small enough for one Codex run?
- [ ] Is this one finding / one fix / one review?
- [ ] Did I choose the correct repository?
  - `oidc-starter-agent` for analyzer/rule/detector/baseline work
  - `oidc-starter` for starter/package/sample hardening fixes
- [ ] Did I reference only the AI contracts needed for this task?

Commonly used:
- `/ai/agent-rules.md`
- `/ai/token-budget.md`

Use when needed:
- `/ai/project-context.md`
- `/ai/current-status.md`

- [ ] Did I clearly say whether this is:
  - implementation,
  - review-only,
  - cleanup,
  - audit finding fix?
- [ ] Did I define the stop condition?
- [ ] Did I forbid unrelated refactors?
- [ ] Did I say whether Codex should run tests or only provide commands?
- [ ] Did I include the exact finding/report excerpt if this is an audit fix?

## Explicit permissions to decide

Before sending a prompt, explicitly decide whether Codex may:

- [ ] run targeted tests
- [ ] run full test suite
- [ ] run full solution build
- [ ] run CLI smoke audit
- [ ] update docs / README / baseline files
- [ ] update package version / release notes
- [ ] inspect broader repository areas
- [ ] modify shared infrastructure
- [ ] change public APIs
- [ ] refactor existing code
- [ ] clean up temporary/generated files

If not explicitly allowed, assume the answer is no.

## Before allowing broader scope

Ask:

- [ ] Why is broader scanning needed?
- [ ] Which files or areas will be inspected?
- [ ] Can this be solved with targeted search instead?
- [ ] Is this still the same task?
- [ ] Should this become a separate task?

Do not approve broad repository scans by default.

## Before accepting Codex output

Check:

- [ ] Did Codex modify only expected files?
- [ ] Did Codex avoid unrelated refactors?
- [ ] Did Codex avoid unrelated formatting changes?
- [ ] Did Codex add or update focused tests when behavior changed?
- [ ] Did Codex avoid committing generated audit reports?
- [ ] Did Codex report exact commands and results?
- [ ] Did Codex distinguish code failures from environment/sandbox issues?
- [ ] Did Codex mention any limitations or follow-up items?

## Before committing

Check:

- [ ] `git diff` is small and focused.
- [ ] No generated reports are staged.
- [ ] No temporary files are staged.
- [ ] No unrelated baseline statuses changed.
- [ ] No unrelated docs changed.
- [ ] Tests are green or failures are understood.
- [ ] Commit message matches the actual change.

Useful commands:

```text
# Show current working tree status.
git status

# Show a compact summary of unstaged changes.
git diff --stat

# Show full unstaged changes.
git diff

# Show a compact summary of staged changes.
git diff --cached --stat

# Show full staged changes.
git diff --cached

# Build the whole oidc-starter-agent solution.
dotnet build .\OidcStarter.Agent.sln

# Run the full oidc-starter-agent test suite without rebuilding/restoring.
dotnet test .\tests\OidcStarter.Agent.Tests\OidcStarter.Agent.Tests.csproj --no-build --no-restore --logger "console;verbosity=normal"

# Run starter audit against the current repository and write a temporary local report.
dotnet run --no-build --project .\src\OidcStarter.Agent.Cli\OidcStarter.Agent.Cli.csproj -- audit starter --repo . --out .\tmp-audit-starter.md

# Run the backward-compatible hardening audit alias against the current repository and write a temporary local report.
dotnet run --no-build --project .\src\OidcStarter.Agent.Cli\OidcStarter.Agent.Cli.csproj -- audit hardening --repo . --out .\tmp-audit-hardening.md

# Remove the temporary starter audit report.
Remove-Item .\tmp-audit-starter.md -ErrorAction SilentlyContinue

# Remove the temporary hardening audit report.
Remove-Item .\tmp-audit-hardening.md -ErrorAction SilentlyContinue

# Run starter audit against the external oidc-starter repository and write audit-report.md in the current directory.
dotnet run --project .\src\OidcStarter.Agent.Cli -- audit starter --repo "C:\Repos\Academy\oidc-starter" --out ".\audit-report.md"

# Remove the generated external audit report.
Remove-Item .\audit-report.md -ErrorAction SilentlyContinue