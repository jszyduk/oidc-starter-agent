# OidcStarter Agent

OidcStarter Agent is a .NET CLI analyzer and future agent host for the separate `oidc-starter` repository.

It analyzes `oidc-starter` from the outside as a local, read-only tool. This repository is intentionally separate from `oidc-starter` and should not modify that project.

## Current Status

The current implemented auditor is the **OidcStarter Hardening Auditor**.

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
dotnet run --project src/OidcStarter.Agent.Cli -- audit hardening --repo "C:\Repos\oidc-starter" --out "audit-report.md"
```

## Development

```powershell
dotnet build .\OidcStarter.Agent.sln
dotnet test .\tests\OidcStarter.Agent.Tests\OidcStarter.Agent.Tests.csproj
```

## Architecture

- `OidcStarter.Agent.Cli`: Console entry point, command parsing, audit execution, and report output.
- `OidcStarter.Agent.Core`: Shared models and interfaces for auditors and rules.
- `OidcStarter.Agent.Auditors.Hardening`: Repository scanner, deterministic hardening rules, hardening auditor, and Markdown report writer.
- `OidcStarter.Agent.Tests`: Unit tests for scanner and rules.

## Roadmap

- Improve deterministic hardening rules.
- Add JSON report output.
- Add LLM report interpretation.
- Add Azure OpenAI-compatible abstraction later.
- Add more auditors in separate namespaces and projects.
