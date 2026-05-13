namespace OidcStarter.Agent.Core;

public interface IAuditRule
{
    string RuleId { get; }

    string Title { get; }

    IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot);
}
