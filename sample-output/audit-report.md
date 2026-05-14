# OidcStarter Hardening Audit Report

Sample output for documentation purposes. This report is illustrative and was not generated from a real audit run.

- Auditor: OidcStarter Hardening Auditor
- Generated: 2026-05-13T20:00:00.0000000+00:00

## Summary

- Critical: 1
- High: 1
- Medium: 1
- Low: 1
- Info: 0

## Findings

### Critical

#### HARDENING-005: Suspicious browser token storage detected

- Severity: Critical
- File: `src/app/auth.ts`
- Description: Suspicious frontend token storage pattern found.
- Recommendation: Avoid storing OIDC tokens in browser localStorage or sessionStorage. Prefer cookie-backed BFF session handling.

### High

#### HARDENING-004: No likely complete BFF antiforgery flow detected

- Severity: High
- Description: No likely complete browser-to-BFF antiforgery flow was detected.
- Recommendation: Baseline BFF-CSRF-002: ensure a browser-to-BFF antiforgery flow exists, including backend antiforgery configuration, token issuing/storage, and frontend/header usage or documented header convention.

### Medium

#### HARDENING-006: No local Keycloak setup detected

- Severity: Medium
- Description: No likely local Keycloak setup was found.
- Recommendation: Include or document a local Keycloak setup, such as docker-compose configuration and realm import files.

### Low

#### HARDENING-008: README.md is missing

- Severity: Low
- Description: The repository root README.md file was not found.
- Recommendation: Add a README.md that explains the BFF starter, setup steps, authentication flow, and security expectations.

## Recommendations

- Avoid storing OIDC tokens in browser localStorage or sessionStorage. Prefer cookie-backed BFF session handling.
- Baseline BFF-CSRF-002: ensure a browser-to-BFF antiforgery flow exists, including backend antiforgery configuration, token issuing/storage, and frontend/header usage or documented header convention.
- Include or document a local Keycloak setup, such as docker-compose configuration and realm import files.
- Add a README.md that explains the BFF starter, setup steps, authentication flow, and security expectations.
