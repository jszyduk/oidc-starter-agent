using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class UnauthorizedForbiddenBehaviorTestsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-027";

    public override string Title => "No focused unauthorized/forbidden behavior tests detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = UnauthorizedForbiddenBehaviorTestDetector.Inspect(snapshot);
        if (result.HasAllBehaviors)
        {
            return [];
        }

        var missing = string.Join(", ", result.MissingCategories);

        return [Finding(
            FindingSeverity.Medium,
            $"Missing likely behavior tests for: {missing}.",
            "Baseline TEST-READINESS-003: add tests for unauthenticated requests and insufficient-permission/forbidden cases so authorization failures do not regress silently.",
            result.EvidencePath)];
    }
}
