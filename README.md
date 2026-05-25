# OidcStarter Agent

OidcStarter Agent is a .NET CLI analyzer and future agent host for the separate `oidc-starter` repository.

It analyzes `oidc-starter` from the outside as a local, read-only tool. This repository is intentionally separate from `oidc-starter` and should not modify that project.

## Current Status

The current implemented auditor is the **OidcStarter Starter Hardening Auditor**. It audits the `oidc-starter` starter/package repository itself, including the reusable BFF package and sample backend. A future consumer integration auditor may audit applications that use the package.

Status: v1 foundation / deterministic analyzer only.

## What It Does

- Scans a local `oidc-starter` repository.
- Runs hardening and configuration rules.
- Generates a Markdown report.

## What It Does Not Do Yet

- Does not modify code.
- Does not create pull requests.
- Does not use LLMs or OpenAI yet.
- Does not perform a full security audit.

## Usage

```powershell
dotnet run --project src/OidcStarter.Agent.Cli -- audit starter --repo "C:\Repos\oidc-starter" --out "audit-report.md"
```

`audit starter` runs the Starter Hardening Auditor against the `oidc-starter` starter/package repository. `audit hardening` is kept as a backward-compatible alias for the same auditor. A Consumer Integration Auditor is future work and is not implemented yet.

## Starter Hardening Auditor v1 Checkpoint

This repository currently provides a Starter Hardening Auditor for the `oidc-starter` repository itself. The preferred command is `audit starter`; `audit hardening` remains available as a backward-compatible alias.

The auditor is package-aware:

- `src/OidcStarter.AspNetCore.Bff` is treated as the reusable NuGet package and primary source of truth for BFF registration/configuration.
- `src/Backend` is treated as a sample/example consumer.
- `src/OidcStarter.AspNetCore.Bff.Tests` is treated as tests/evidence, not production configuration.

The latest manual run against the real `oidc-starter` repository produced no findings. Generated audit reports are runtime artifacts and should not be committed as latest state.

Implemented starter-auditor coverage includes:

- BFF login/logout/me endpoint presence.
- MVC controller requirement for BFF auth endpoints.
- Browser token storage checks.
- BFF frontend session/cookie behavior.
- Local logout clearing the application session/cookie.
- IdP/OIDC logout awareness through implementation evidence or documented caveats.
- Authentication cookie `HttpOnly`, `SecurePolicy`, and `SameSite` configuration.
- BFF antiforgery flow detection.
- Unsafe HTTP method antiforgery coverage.
- Focused login/logout/me behavior test readiness.
- Focused antiforgery behavior test readiness, including package antiforgery attribute evidence.
- Focused unauthorized/forbidden behavior test readiness.
- Package/sample compatibility evidence through tests or build-together signals.
- ASP.NET Core authentication/authorization middleware order.
- Local Keycloak setup and development-only labeling.
- Production hardening documentation.

This coverage is deterministic and heuristic; it is not a formal security compliance claim.
Baseline status values such as `Implemented` describe analyzer coverage in this repository, not a
guarantee that every audited target repository passes the rule.

## Development

```powershell
dotnet build .\OidcStarter.Agent.sln
dotnet test .\tests\OidcStarter.Agent.Tests\OidcStarter.Agent.Tests.csproj
```

## Architecture

- `OidcStarter.Agent.Cli`: Console entry point, command parsing, audit execution, and report output.
- `OidcStarter.Agent.Core`: Shared models and interfaces for auditors and rules.
- `OidcStarter.Agent.Auditors.Starter`: Repository scanner, deterministic starter hardening rules, starter hardening auditor, and Markdown report writer.
- `OidcStarter.Agent.Tests`: Unit tests for scanner and rules.

## Roadmap

- CORS explicit origin checks.
- Secrets scanning.
- SPA-focused rules.
- Consumer Integration Auditor for applications using the NuGet package.
- Add JSON report output.
- Optional future LLM interpretation layer for explaining findings and prioritizing backlog.
