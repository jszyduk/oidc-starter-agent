using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AntiforgeryBehaviorTestsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-026";

    public override string Title => "No focused antiforgery behavior tests detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = AntiforgeryBehaviorTestDetector.Inspect(snapshot);
        if (result.HasSufficientCoverage)
        {
            return [];
        }

        var missing = string.Join(", ", result.MissingCategories);

        return [Finding(
            FindingSeverity.High,
            $"Missing likely antiforgery behavior test coverage for: {missing}.",
            "Baseline TEST-READINESS-002: add tests for BFF antiforgery token issuing and request validation behavior, including unsafe endpoint protection where applicable.",
            result.EvidencePath)];
    }
}
