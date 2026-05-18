# Security Baseline v1 for OIDC/BFF Starter

## Purpose

This baseline defines expected security and hardening requirements for an OIDC/BFF reference starter built with ASP.NET Core, cookie-backed authentication, and a browser frontend.

It is intended to guide deterministic analyzer rules in `oidc-starter-agent`. It is not a full penetration test checklist, does not claim formal compliance, and is not tied to the current implementation state of `oidc-starter`.

The baseline should be used to compare expected security posture against actual repository state, identify gaps, and shape a future hardening backlog. Baseline v1 is expected to evolve as analyzer coverage and starter architecture mature.

## Supported Auth Modes

`oidc-starter` may support two authentication modes with different security profiles. BFF is the recommended direction for this starter, especially for production-quality usage. SPA mode can still be useful as a supported, demo, or browser-client mode, but rules should not be assumed to apply equally to both modes.

### BFF Mode

BFF mode is the recommended/default target architecture for production-quality usage. The backend owns OIDC protocol interaction, and the browser frontend relies on a backend session/cookie rather than directly managing OAuth tokens.

Security focus:

- Cookie security.
- CSRF/antiforgery.
- Backend login/logout.
- Local session handling.
- Server-side token handling.
- ASP.NET Core middleware and hosting configuration.

### SPA Mode

SPA mode is a supported/demo/browser-client mode. The frontend owns OIDC protocol interaction, and the browser application behaves as a public client.

Security focus:

- Authorization Code + PKCE.
- No implicit flow.
- No client secret in frontend.
- Redirect URI restrictions.
- Browser token exposure/storage risk.
- XSS/token theft risk.
- Frontend configuration.

A rule may apply to BFF, SPA, or Both. Future analyzer output should interpret findings through the relevant mode rather than applying BFF-specific or SPA-specific expectations blindly.

## Source Families

- OAuth 2.0 Security Best Current Practice / RFC 9700: Provides current OAuth security expectations, including safer flow choices, redirect URI handling, client authentication concerns, token handling, and attacks to avoid.
- OAuth 2.0 for Browser-Based Applications: Frames the special risks of browser clients, especially token exposure, storage, and patterns that keep sensitive tokens away from frontend JavaScript.
- OWASP OAuth2 Cheat Sheet / OWASP CSRF Cheat Sheet: Provides practical application security guidance for OAuth usage and browser request forgery defenses.
- Microsoft ASP.NET Core security guidance: Provides platform-specific guidance for cookies, SameSite, antiforgery, authentication, authorization, HTTPS, hosting, and deployment behavior.

## Baseline Levels

### Level 1 - Reference Starter Baseline

Requirements expected from a reusable sample or reference implementation. These should be practical, visible, testable, and documented enough that consumers do not copy unsafe defaults.

### Level 2 - Production Hardening Baseline

Requirements expected before using the starter in a real production application. These include stronger configuration controls, explicit deployment assumptions, and tests for security-sensitive behavior.

### Level 3 - Enterprise / Strict Security Baseline

Requirements for stricter environments with stronger operational, compliance, audit, or enterprise governance expectations. These may require environment-specific policy, monitoring, rotation, and deployment controls beyond the starter itself.

## Rule Catalogue

Allowed status values:

- Planned: No analyzer rule currently exists.
- Implemented: The analyzer has a reasonably direct rule for the baseline requirement.
- Partially Implemented: The analyzer currently detects only a weak signal, proxy condition, or incomplete part of the requirement.
- Needs Review: The baseline rule or detection approach needs more design.

Status is about analyzer coverage in `oidc-starter-agent`, not about whether `oidc-starter` already implements the behavior.

| Rule ID | Level | Applies To | Area | Requirement | Rationale | Source Family | Detection Strategy | Suggested Severity | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OIDC-FLOW-001 | Level 1 | Both | OIDC / OAuth flow | Authorization Code flow should be used for browser sign-in. | Authorization Code is the expected modern flow for OIDC sign-in and avoids legacy browser token delivery patterns. | OAuth 2.0 Security BCP / Browser-Based Apps | Scan auth configuration and docs for response type, OIDC handler configuration, and absence of implicit-only setup. | High | Planned |
| OIDC-FLOW-002 | Level 1 | Both | OIDC / OAuth flow | Implicit flow should not be used. | Implicit flow exposes tokens through browser-facing redirects and is not appropriate for a modern starter. | OAuth 2.0 Security BCP / Browser-Based Apps / OWASP OAuth2 | Search configuration and docs for `response_type=token`, `id_token token`, or implicit grant enablement. | High | Planned |
| OIDC-FLOW-003 | Level 1 | Both | OIDC / OAuth flow | PKCE should be used where applicable. | PKCE mitigates authorization code interception and is especially important for browser public clients. | OAuth 2.0 Security BCP / Browser-Based Apps / OWASP OAuth2 | Scan OIDC options and identity provider config for PKCE-related settings and documentation. | Medium | Planned |
| OIDC-FLOW-004 | Level 1 | Both | OIDC / OAuth flow | Redirect URIs should be explicit and not wildcard-based. | Overbroad redirect URIs increase the impact of redirect and code interception attacks. | OAuth 2.0 Security BCP / OWASP OAuth2 | Scan identity provider realm/config JSON and docs for wildcard redirect URI values. | High | Planned |
| OIDC-FLOW-005 | Level 1 | Both | OIDC / OAuth flow | OIDC authority or issuer should be configured explicitly. | Explicit issuer configuration reduces accidental trust in the wrong authority. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Scan backend/frontend config and sample settings for authority, issuer, metadata address, or equivalent options. | Medium | Planned |
| OIDC-FLOW-006 | Level 1 | Both | OIDC / OAuth flow | Client secrets must not be exposed to browser frontend code. | Browser code is public; secrets in frontend assets are not secrets. | Browser-Based Apps / OWASP OAuth2 | Scan frontend files and public assets for client secret names and likely secret values. | Critical | Planned |
| BFF-ARCH-001 | Level 1 | BFF | BFF architecture | Browser frontend should not store access tokens or refresh tokens in localStorage or sessionStorage. | Persistent browser token storage increases exposure to XSS and extension compromise. | Browser-Based Apps / OWASP OAuth2 | Scan frontend TypeScript/HTML for token storage patterns using localStorage/sessionStorage. | Critical | Implemented |
| BFF-ARCH-002 | Level 1 | BFF | BFF architecture | Frontend should rely on backend session/cookie where BFF mode is used. | BFF architecture keeps tokens server-side and gives the browser a constrained session representation. | Browser-Based Apps / Microsoft ASP.NET Core security guidance | Scan frontend API/auth services and backend auth setup for cookie/session usage rather than browser bearer token handling. | High | Implemented |
| BFF-ARCH-003 | Level 1 | BFF | BFF architecture | BFF auth endpoints should be implemented consistently as MVC controller actions for this reference starter. | Consistent controller actions are explicit, testable, and easier for starter users to understand. | Microsoft ASP.NET Core security guidance | Detect Minimal API auth route mappings for `/me`, `/login`, and `/logout`. | Medium | Implemented |
| BFF-ARCH-004 | Level 1 | BFF | BFF architecture | Current-user/session-state endpoint should exist. | Browser clients need a safe way to discover authenticated session state without direct token access. | Browser-Based Apps / Microsoft ASP.NET Core security guidance | Detect MVC controller route/action for `me` or equivalent current-user endpoint. | Medium | Implemented |
| BFF-ARCH-005 | Level 1 | BFF | BFF architecture | Login endpoint should exist. | The starter should expose a clear backend entry point for initiating sign-in. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Detect MVC controller route/action for login. | High | Implemented |
| BFF-ARCH-006 | Level 1 | BFF | BFF architecture | Logout endpoint should exist. | The starter should expose a clear backend entry point for ending the local session. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Detect MVC controller route/action for logout. | High | Implemented |
| BFF-ARCH-007 | Level 1 | BFF | BFF architecture | Logout should clear local application session/cookie. | Logout that leaves the application cookie intact does not end the local authenticated session. | Microsoft ASP.NET Core security guidance / OWASP OAuth2 | Scan logout action for sign-out calls against local cookie scheme. | High | Implemented |
| BFF-ARCH-008 | Level 2 | BFF | BFF architecture | Logout should account for identity-provider sign-out where applicable. | Depending on the provider and app model, users may expect logout to end or coordinate the upstream identity provider session. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Scan logout flow and docs for OIDC sign-out behavior, callback paths, or explicit caveats. | Medium | Implemented |
| BFF-COOKIE-001 | Level 1 | BFF | Cookies and session security | Authentication cookie should be HttpOnly. | HttpOnly reduces cookie exposure to frontend JavaScript. | Microsoft ASP.NET Core security guidance / OWASP CSRF | Scan cookie authentication options for `HttpOnly` configuration or framework defaults plus documentation. | High | Implemented |
| BFF-COOKIE-002 | Level 1 | BFF | Cookies and session security | Authentication cookie should use Secure in production. | Secure cookies prevent transmission over plain HTTP in production. | Microsoft ASP.NET Core security guidance | Scan cookie options, environment-specific config, and production docs for `SecurePolicy`. | High | Implemented |
| BFF-COOKIE-003 | Level 1 | BFF | Cookies and session security | SameSite should be configured intentionally. | SameSite affects CSRF resistance and OIDC redirect compatibility; accidental defaults can break or weaken behavior. | Microsoft ASP.NET Core security guidance / OWASP CSRF | Scan cookie and correlation cookie options for SameSite values and explanatory docs. | Medium | Implemented |
| BFF-COOKIE-004 | Level 1 | BFF | Cookies and session security | Cookie name should be explicit enough to avoid confusion or collisions. | Explicit cookie names make starter behavior clear and reduce collisions with host applications. | Microsoft ASP.NET Core security guidance | Scan cookie auth options for configured cookie name. | Low | Implemented |
| BFF-COOKIE-005 | Level 1 | BFF | Cookies and session security | Cookie lifetime/session duration should be explicit. | Starter consumers should see the expected session lifetime rather than inherit unclear defaults. | Microsoft ASP.NET Core security guidance | Scan auth cookie options for expiration/lifetime settings and docs. | Medium | Implemented |
| BFF-COOKIE-006 | Level 2 | BFF | Cookies and session security | Sliding expiration should be intentional, not accidental. | Sliding sessions affect risk and user experience; production apps should make this choice consciously. | Microsoft ASP.NET Core security guidance | Scan cookie options and docs for sliding expiration setting or rationale. | Low | Implemented |
| BFF-CSRF-001 | Level 1 | BFF | CSRF / antiforgery | State-changing BFF endpoints should be protected against CSRF. | Cookie-authenticated browser requests are susceptible to CSRF unless protected by tokens, origin checks, or equivalent defenses. | OWASP CSRF / Microsoft ASP.NET Core security guidance | Detect antiforgery services/middleware/attributes and state-changing endpoint coverage. | High | Planned |
| BFF-CSRF-002 | Level 1 | BFF | CSRF / antiforgery | Antiforgery flow should be present for browser-to-BFF requests where cookies are used. | A browser frontend needs a practical way to obtain and send antiforgery tokens. | OWASP CSRF / Microsoft ASP.NET Core security guidance | Scan for antiforgery API usage, token endpoint/header conventions, and frontend header usage. | High | Implemented |
| BFF-CSRF-003 | Level 1 | BFF | CSRF / antiforgery | Antiforgery token/header naming should be documented. | Consumers need to know how frontend requests are expected to carry the token. | Microsoft ASP.NET Core security guidance / OWASP CSRF | Scan README/docs for token/header names and frontend request examples. | Medium | Planned |
| BFF-CSRF-004 | Level 1 | BFF | CSRF / antiforgery | Unsafe HTTP methods should be protected. | POST, PUT, PATCH, and DELETE requests can change state and need CSRF defenses in cookie-authenticated flows. | OWASP CSRF / Microsoft ASP.NET Core security guidance | Detect unsafe endpoints and require antiforgery attributes, filters, or middleware coverage. | High | Implemented |
| BFF-CSRF-005 | Level 1 | BFF | CSRF / antiforgery | SameSite should not be treated as the only CSRF defense for sensitive operations. | SameSite is useful defense-in-depth but should not be the sole protection for sensitive state changes. | OWASP CSRF / Microsoft ASP.NET Core security guidance | Scan docs/config for SameSite-only claims without antiforgery or equivalent request validation. | Medium | Planned |
| BFF-AUTHZ-001 | Level 1 | Both | Authorization and claims | Authorization foundation should exist. | A starter should demonstrate protected endpoints and authorization concepts, not only authentication. | Microsoft ASP.NET Core security guidance / OWASP OAuth2 | Scan backend/frontend samples for authorization services, middleware, policies, route guards, or protected sample behavior. | Medium | Implemented |
| BFF-AUTHZ-002 | Level 1 | Both | Authorization and claims | Role/claim mapping should be explicit and testable. | OIDC provider claims vary; explicit mapping prevents hidden assumptions. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Scan for claims transformation, role mapping extension points, and tests. | Medium | Planned |
| BFF-AUTHZ-003 | Level 1 | Both | Authorization and claims | Sample role mapping should be documented. | Starter users need a clear example of adapting provider-specific claims. | Microsoft ASP.NET Core security guidance | Scan docs and sample code for role mapping explanation. | Low | Planned |
| BFF-AUTHZ-004 | Level 2 | Both | Authorization and claims | Unauthorized and forbidden cases should be tested. | Security behavior should be verified for anonymous and insufficiently privileged users. | Microsoft ASP.NET Core security guidance / OWASP OAuth2 | Scan tests for 401/403 cases and protected endpoint scenarios. | Medium | Planned |
| BFF-AUTHZ-005 | Level 1 | Both | Authorization and claims | Claims exposed to the frontend should be minimal and intentional. | Frontend session payloads should avoid leaking unnecessary identity or authorization data. | Browser-Based Apps / OWASP OAuth2 | Scan current-user endpoint response models, SPA user profile handling, and docs for exposed claims. | Medium | Planned |
| BFF-CONFIG-001 | Level 1 | Both | Configuration and secrets | Secrets should not be committed to source control. | Committed secrets can compromise identity providers, clients, or environments. | OWASP OAuth2 / Microsoft ASP.NET Core security guidance | Scan tracked config, docs, and sample files for likely secrets and private keys. | Critical | Planned |
| BFF-CONFIG-002 | Level 1 | Both | Configuration and secrets | Environment-specific config should be separated. | Development settings should not silently become production defaults. | Microsoft ASP.NET Core security guidance | Scan appsettings files, frontend environment files, launch profiles, docs, and environment naming. | Medium | Planned |
| BFF-CONFIG-003 | Level 1 | Both | Configuration and secrets | Development Keycloak config should be clearly marked as development-only. | Local identity provider setup is useful but should not be mistaken for production guidance. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Scan Keycloak/docker docs and config for development-only warnings. | Low | Implemented |
| BFF-CONFIG-004 | Level 1 | Both | Configuration and secrets | Production configuration assumptions should be documented. | Starter consumers need to know what must change before production use. | Microsoft ASP.NET Core security guidance / OWASP OAuth2 | Scan README/docs for production hardening caveats and required settings. | Medium | Implemented |
| BFF-CONFIG-005 | Level 1 | Both | Configuration and secrets | CORS origins should be explicit. | Wildcard or overly broad CORS can expose authenticated APIs to unintended browser origins. | Browser-Based Apps / Microsoft ASP.NET Core security guidance | Scan CORS policy configuration for wildcard origins and environment-specific origin lists. | High | Planned |
| BFF-CONFIG-006 | Level 1 | Both | Configuration and secrets | HTTPS assumptions should be documented. | OIDC redirects, secure cookies, and production browser security rely on HTTPS. | OAuth 2.0 Security BCP / Microsoft ASP.NET Core security guidance | Scan docs and hosting config for HTTPS expectations. | Medium | Planned |
| ASPNET-HOST-001 | Level 1 | BFF | ASP.NET Core hosting/security middleware | Authentication and authorization middleware should be registered in the correct order. | Incorrect middleware order can bypass or break authentication/authorization behavior. | Microsoft ASP.NET Core security guidance | Scan startup/program files for `UseAuthentication` before `UseAuthorization` and routing placement. | High | Implemented |
| ASPNET-HOST-002 | Level 2 | BFF | ASP.NET Core hosting/security middleware | HTTPS redirection should be considered for production. | Production apps should avoid serving authenticated traffic over plain HTTP. | Microsoft ASP.NET Core security guidance | Scan hosting config and docs for HTTPS redirection or explicit reverse-proxy termination assumptions. | Medium | Planned |
| ASPNET-HOST-003 | Level 2 | BFF | ASP.NET Core hosting/security middleware | Forwarded headers should be documented or configured for reverse proxy deployments. | Reverse proxies affect scheme, host, redirects, secure cookies, and OIDC callback behavior. | Microsoft ASP.NET Core security guidance | Scan for forwarded headers middleware/config and deployment notes. | Medium | Planned |
| ASPNET-HOST-004 | Level 1 | BFF | ASP.NET Core hosting/security middleware | Exception handling behavior should differ between development and production. | Production should avoid leaking stack traces and sensitive error details. | Microsoft ASP.NET Core security guidance | Scan startup/program files for environment-specific developer exception page vs production handler. | Medium | Planned |
| TEST-READINESS-001 | Level 1 | BFF | Tests and release readiness | Login/logout/me behavior should have tests. | BFF auth endpoints are core starter behavior and should not regress silently. | Microsoft ASP.NET Core security guidance | Scan test projects for auth endpoint tests or route behavior assertions. | Medium | Partially Implemented |
| TEST-READINESS-002 | Level 1 | BFF | Tests and release readiness | Antiforgery behavior should have tests. | CSRF defenses are security-sensitive and should be verified. | OWASP CSRF / Microsoft ASP.NET Core security guidance | Scan tests for antiforgery token/header success and failure cases. | High | Planned |
| TEST-READINESS-003 | Level 1 | Both | Tests and release readiness | Unauthorized/forbidden behavior should have tests. | Access-control regressions should be caught before release. | Microsoft ASP.NET Core security guidance / OWASP OAuth2 | Scan tests for 401/403 scenarios. | Medium | Planned |
| TEST-READINESS-004 | Level 2 | Both | Tests and release readiness | Package/sample compatibility should be tested. | A reusable starter should verify that package and sample remain compatible. | Microsoft ASP.NET Core security guidance | Scan CI/test setup for package/sample integration tests. | Medium | Planned |
| TEST-READINESS-005 | Level 1 | Both | Tests and release readiness | README should document production hardening caveats. | Starter users need clear warnings about what is sample-only and what must be configured for production. | OWASP OAuth2 / Microsoft ASP.NET Core security guidance | Scan README/docs for production hardening section and caveats. | Low | Partially Implemented |

## Mapping to Current Analyzer Rules

| Existing Analyzer Rule ID | Related Baseline Rule ID | Notes |
| --- | --- | --- |
| HARDENING-001 | BFF-ARCH-005 | Implemented: checks that a likely MVC login endpoint exists. |
| HARDENING-002 | BFF-ARCH-006 | Implemented: checks that a likely MVC logout endpoint exists. |
| HARDENING-003 | BFF-ARCH-004 | Implemented: checks that a likely current-user/session-state endpoint exists. |
| HARDENING-004 | BFF-CSRF-002 | Implemented: detects a likely browser-to-BFF antiforgery flow, including backend setup, token issuing/storage, and frontend/header usage or documented header convention. Still heuristic; does not verify unsafe endpoint coverage. |
| HARDENING-005 | BFF-ARCH-001 | Implemented: checks suspicious frontend localStorage/sessionStorage token storage patterns. |
| HARDENING-006 | BFF-CONFIG-003 | Implemented: checks concrete local Keycloak setup evidence and development-only labeling tied to Keycloak/local IdP context in README/docs/config. Static and heuristic. |
| HARDENING-007 | TEST-READINESS-001 | Partial: detects backend/package tests generally, but not login/logout/me behavior tests specifically. |
| HARDENING-008 | TEST-READINESS-005 | Partial: checks README existence. HARDENING-016 covers production hardening caveat content in README/docs, but does not require that content to be in README.md specifically. |
| HARDENING-009 | BFF-ARCH-003 | Implemented: reports BFF auth endpoints implemented with Minimal API mappings instead of MVC controller actions. |
| HARDENING-010 | BFF-ARCH-007 | Implemented: checks that a likely logout action clears the local application session/cookie via SignOutAsync, SignOut, or SignOutResult near the logout action. |
| HARDENING-011 | BFF-COOKIE-001 | Implemented: checks likely authentication cookie HttpOnly configuration while ignoring comments and likely test files. |
| HARDENING-012 | BFF-COOKIE-002 | Implemented: checks likely authentication cookie SecurePolicy configuration while ignoring comments and likely test files. |
| HARDENING-013 | BFF-COOKIE-003 | Implemented: checks likely authentication cookie SameSite configuration while ignoring comments and likely test files. |
| HARDENING-014 | ASPNET-HOST-001 | Implemented: checks likely ASP.NET Core pipeline files for UseAuthentication before UseAuthorization and reports missing UseAuthentication when UseAuthorization is present. Static and heuristic. |
| HARDENING-015 | BFF-ARCH-002 | Implemented: detects suspicious browser token or bearer-auth handling in frontend code that appears to participate in BFF mode, while ignoring clearly SPA-specific files. Static and heuristic. |
| HARDENING-016 | BFF-CONFIG-004 / TEST-READINESS-005 | Implemented for BFF-CONFIG-004 and partial for TEST-READINESS-005: checks README/docs for likely production hardening notes and concrete OIDC/BFF hardening topics, while ignoring analyzer baseline docs and generated reports. Static and heuristic. |
| HARDENING-017 | BFF-ARCH-008 | Implemented: checks for likely OIDC/IdP sign-out implementation or documentation explaining local-vs-provider logout behavior. Static and heuristic. |
| HARDENING-018 | BFF-COOKIE-005 | Implemented: checks package-aware authentication cookie lifetime/session duration configuration. Static and heuristic. |
| HARDENING-019 | BFF-COOKIE-006 | Implemented: checks package-aware explicit sliding expiration configuration. Static and heuristic. |
| HARDENING-020 | BFF-COOKIE-004 | Implemented: checks package-aware explicit authentication cookie name configuration. Static and heuristic. |
| HARDENING-021 | BFF-CSRF-004 | Implemented: checks package-aware unsafe MVC endpoints for likely antiforgery protection through standard or oidc-starter action/controller antiforgery attributes, global MVC filters, or clear global antiforgery signals. Static and heuristic. |
| HARDENING-022 | BFF-AUTHZ-001 | Implemented: checks for authorization setup or extension-point signals plus protected endpoint/sample usage. Static and heuristic. |

## Future Analyzer Implementation Notes

Deterministic rules should produce facts: files inspected, patterns found, suspected gaps, and why a finding was emitted. They should avoid presenting broad security conclusions that the static analyzer cannot prove.

A future LLM layer, if added, should interpret findings, explain tradeoffs, and prioritize backlog items. It should not replace deterministic rule evidence.

Implemented status means analyzer coverage exists in `oidc-starter-agent`. It does not mean the external `oidc-starter` repository currently passes the rule. Findings from `audit-report.md` are run-specific output and should not directly change baseline status.

Future findings should include or infer the relevant auth mode where possible. BFF findings should not be blindly applied to SPA mode, and SPA findings should not be blindly applied to BFF mode. Some findings may apply to Both. A future CLI may support explicit mode selection, for example `oidc-agent audit hardening --mode bff`, `oidc-agent audit hardening --mode spa`, or `oidc-agent audit hardening --mode both`.

Each future rule should reference one or more baseline rule IDs so findings can be traced back to this baseline. Rules should avoid tight coupling to exact file names unless the file name is itself part of the expected convention.

Rules should prefer architectural and security requirements over current implementation details. False-positive risk should be considered before enforcing a rule, especially for configuration that may be supplied outside the repository.

## Candidate Rules for Next Implementation Phase

### BFF candidates


### SPA candidates

- Detect implicit flow usage.
- Detect Authorization Code + PKCE configuration.
- Detect client secret exposure in frontend config.
- Harden browser token storage detection.
- Detect wildcard redirect URIs in frontend/IdP config.

### Both

- Detect likely committed secrets in tracked configuration and frontend/backend files.
- Detect wildcard or overly broad CORS origins.
- Detect tests for unauthorized and forbidden behavior.
