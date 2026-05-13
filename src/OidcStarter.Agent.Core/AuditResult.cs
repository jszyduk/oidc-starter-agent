namespace OidcStarter.Agent.Core;

public sealed record AuditResult(
    string AuditorName,
    IReadOnlyList<AuditFinding> Findings);
