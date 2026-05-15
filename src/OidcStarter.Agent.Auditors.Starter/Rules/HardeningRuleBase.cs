using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public abstract class HardeningRuleBase : IAuditRule
{
    public abstract string RuleId { get; }

    public abstract string Title { get; }

    public abstract IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot);

    protected AuditFinding Finding(
        FindingSeverity severity,
        string description,
        string recommendation,
        string? filePath = null)
    {
        return new AuditFinding(RuleId, Title, severity, description, filePath, recommendation);
    }
}
