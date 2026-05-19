using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthEndpointBehaviorTestsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-025";

    public override string Title => "No focused login/logout/me behavior tests detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = AuthEndpointBehaviorTestDetector.Inspect(snapshot);
        if (result.HasAllBehaviors)
        {
            return [];
        }

        var missing = string.Join(", ", result.MissingBehaviors);

        return [Finding(
            FindingSeverity.Medium,
            $"Missing likely focused behavior tests for: {missing}.",
            "Baseline TEST-READINESS-001: add tests for login, logout, and current-user/session-state behavior so core BFF auth endpoints do not regress silently.",
            result.EvidencePath)];
    }
}
