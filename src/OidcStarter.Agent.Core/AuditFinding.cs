namespace OidcStarter.Agent.Core;

public sealed record AuditFinding(
    string RuleId,
    string Title,
    FindingSeverity Severity,
    string Description,
    string? FilePath,
    string Recommendation);
