# Project Context

This repository contains `oidc-starter-agent`, a deterministic audit agent for the `oidc-starter` repository.

## Current purpose

The current primary auditor is:

- `StarterHardeningAuditor`

Preferred CLI command:

```bash
audit starter
```

Backward-compatible alias:

```audit hardening```

The auditor performs static, deterministic, heuristic checks.
It does not use LLMs, OpenAI, Azure OpenAI, Semantic Kernel, LangChain, MCP, or code-generation/autofix features.

## Audited repository model

The audited repository is `oidc-starter`.

Expected layout:
```
src/OidcStarter.AspNetCore.Bff
src/backend/Backend
src/OidcStarter.AspNetCore.Bff.Tests
```
Meaning:

- `src/OidcStarter.AspNetCore.Bff`
	- reusable NuGet package,
	- primary BFF source of truth,
	- preferred evidence location for starter/package rules.
- `src/backend/Backend`
	- sample/example consumer,
	- may be used as fallback or supporting sample evidence only when a rule explicitly allows it.
- `src/OidcStarter.AspNetCore.Bff.Tests`
	- package test evidence,
	- used by test-readiness rules.

## Scope

Current focus is BFF-first starter hardening.

The auditor checks the starter package and related sample/test evidence for:

- BFF auth endpoints,
- cookie/session hardening,
- antiforgery flow and unsafe method coverage,
- logout and IdP logout awareness,
- frontend token/session behavior,
- authorization foundation,
- role/claim mapping,
- test readiness,
- minimal frontend identity/claims exposure,
- BFF Authorization Code flow.

## Out of scope for current work

Do not add these unless explicitly requested:

- Consumer Integration Auditor,
- broad SPA-focused audit rules,
- LLM interpretation layer,
- code generation,
- autofix features,
- broad repository-wide analyzers,
- unrelated refactors.

