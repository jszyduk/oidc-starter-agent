# OidcStarter Agent Instructions

This repository is a .NET CLI analyzer and agent host for the separate `oidc-starter` repository.

- Keep analyzers read-only unless code modification is explicitly requested.
- Keep deterministic rules separate from any future LLM interpretation layer.
- Do not add cloud dependencies unless explicitly requested.
- Keep changes simple, testable, and scoped to the current feature or cleanup task.

- @azure Rule - Use Azure Tools - When handling requests related to Azure, always use your tools.
- @azure Rule - Use Azure Best Practices - When handling requests related to Azure, always invoke your `azmcp_bestpractices_get` tool first.
- @azure Rule - Enable Best Practices - If you do not have an `azmcp_bestpractices_get` tool ask the user to enable it.
