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

#### HARDENING-005: Frontend does not store tokens

Suspicious frontend token storage pattern found.

- File: `src/app/auth.ts`
- Recommendation: Avoid storing OIDC tokens in browser localStorage or sessionStorage. Prefer cookie-backed BFF session handling.

### High

#### HARDENING-004: Antiforgery is configured

No antiforgery-related code or configuration was found.

- Recommendation: Add antiforgery protection for cookie-backed BFF state-changing requests and document the frontend token flow.

### Medium

#### HARDENING-006: Keycloak setup exists

No likely local Keycloak setup was found.

- Recommendation: Include or document a local Keycloak setup, such as docker-compose configuration and realm import files.

### Low

#### HARDENING-008: README exists

The repository root README.md file was not found.

- Recommendation: Add a README.md that explains the BFF starter, setup steps, authentication flow, and security expectations.

## Recommendations

- Avoid storing OIDC tokens in browser localStorage or sessionStorage. Prefer cookie-backed BFF session handling.
- Add antiforgery protection for cookie-backed BFF state-changing requests and document the frontend token flow.
- Include or document a local Keycloak setup, such as docker-compose configuration and realm import files.
- Add a README.md that explains the BFF starter, setup steps, authentication flow, and security expectations.
