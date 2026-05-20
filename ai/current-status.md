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

Current priority is to use the existing audit findings to improve `oidc-starter` before a possible `v1.0.1` NuGet patch.

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

At the current freeze point, the known active findings in `oidc-starter` are:

### HARDENING-025

Missing focused login/logout behavior tests.

Expected direction:
- add focused tests for login behavior,
- add focused tests for logout behavior,
- avoid runtime behavior changes unless a real bug is found.

### HARDENING-027

Missing unauthorized/forbidden behavior tests.

Expected direction:
- add tests for unauthenticated / unauthorized behavior,
- add tests for insufficient-permission / forbidden behavior,
- avoid changing authorization runtime behavior unless a real bug is found.

### HARDENING-028

Missing package/sample compatibility evidence.

Expected direction:
- add integration/build-together evidence that the sample backend and reusable package remain compatible,
- prefer the smallest maintainable compatibility evidence,
- prefer focused compatibility tests or clear CI/build evidence,
- avoid broad end-to-end test infrastructure unless explicitly requested.

## Recently resolved / clarified findings

### HARDENING-021

Unsafe HTTP method antiforgery coverage.

Status:
- resolved after `oidc-starter` added `OidcStarterValidateAntiforgeryToken`,
- `oidc-starter-agent` now recognizes this custom attribute as valid antiforgery coverage.

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
- Do not create `v1.0.1` release yet.
- Do not commit generated audit reports.

## Suggested next task order

Suggested next task order, unless the user changes priority:

1. Fix `HARDENING-025`.
2. Fix `HARDENING-027`.
3. Fix `HARDENING-028`.
4. Re-run `oidc-starter-agent` audit against `oidc-starter`.
5. If audit is clean, prepare `v1.0.1` release candidate steps separately.