# Current Status

This file captures the current working state for Codex tasks.

This file describes the current working state of `oidc-starter-agent` and its current audit-driven relationship to `oidc-starter`.

Use this together with:

- `/ai/agent-rules.md`
- `/ai/token-budget.md`
- `/ai/project-context.md`

## Current phase

New `StarterHardeningAuditor` rule development is frozen for now.

Do not add new hardening rules unless explicitly requested.

Current priority is documentation and release-readiness support after the latest `oidc-starter`
hardening round. The latest audit smoke against `oidc-starter` reported 0 findings.

## Current auditor status

Repository: `oidc-starter-agent`

Current auditor:

- `StarterHardeningAuditor`

CLI:

- preferred: `audit starter`
- compatibility alias: `audit hardening`

Current scope:

- BFF-first
- package-aware
- deterministic/static/heuristic checks

## Audited repository status

Target repository: `oidc-starter`

Primary product focus:

- `src/OidcStarter.AspNetCore.Bff`
- reusable NuGet package
- BFF path is the current priority

Sample/backend:

- `src/backend/Backend`
- sample/example consumer
- not the primary source of truth when package files exist

Tests:

- `src/OidcStarter.AspNetCore.Bff.Tests`
- package test evidence

## Active audit findings

At the current freeze point, there are no known active findings in `oidc-starter`.

Latest verification:
- `oidc-starter` BFF test project passed 24/24,
- `oidc-starter-agent` audit smoke against `oidc-starter` reported 0 findings,
- generated audit reports remain runtime artifacts and should not be committed.

## Recently resolved / clarified findings

### HARDENING-021

Unsafe HTTP method antiforgery coverage.

Status:
- resolved after `oidc-starter` added `OidcStarterValidateAntiforgeryToken`,
- `oidc-starter-agent` now recognizes this custom attribute as valid antiforgery coverage.

### HARDENING-025

Login/logout/me behavior test readiness.

Status:
- resolved in `oidc-starter` with focused package tests for login, logout, current-user, and
  session-state behavior,
- `oidc-starter-agent` recognizes the focused package test evidence.

### HARDENING-026

Antiforgery behavior test readiness.

Status:
- resolved in `oidc-starter` with focused token issuing, request validation, and unsafe endpoint
  protection evidence,
- `oidc-starter-agent` recognizes package antiforgery attribute/filter evidence,
- detector preprocessing now handles URL string literals without corrupting evidence.

### HARDENING-027

Unauthorized/forbidden behavior test readiness.

Status:
- resolved in `oidc-starter` with package-configured cookie auth event tests for 401 and 403 API
  behavior,
- detector preprocessing now handles URL string literals without corrupting evidence.

### HARDENING-028

Package/sample compatibility evidence.

Status:
- resolved in `oidc-starter` with sample backend project-reference evidence plus a package test
  project MSBuild target that builds the sample backend,
- `oidc-starter-agent` recognizes focused MSBuild target-based build-together evidence in `.csproj`
  files.

### HARDENING-029

Minimal frontend claims exposure.

Status:
- no active finding after detector tightening,
- previous finding was treated as an analyzer false positive / overly broad detection.

### HARDENING-030

BFF Authorization Code flow.

Status:
- no active finding,
- current BFF OIDC flow appears to use Authorization Code flow.

## Current working rules

For the next tasks:

- Fix one finding at a time.
- Prefer tests-only fixes for test-readiness findings.
- Do not add new agent rules.
- Do not refactor unrelated code.
- Do not change public APIs unless required.
- Do not update package version or release artifacts unless explicitly requested.
- Do not commit generated audit reports.

## Known follow-ups

- `PackageSampleCompatibilityTestDetector` has solution-file evidence logic, but `RepositoryScanner`
  may not currently include `.sln` files. This is not a current blocker for `oidc-starter` because
  `.csproj` MSBuild target-based compatibility evidence is recognized.
