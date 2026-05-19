using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class PackageSampleCompatibilityTestsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-028";

    public override string Title => "No package/sample compatibility test evidence detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = PackageSampleCompatibilityTestDetector.Inspect(snapshot);
        if (result.HasCompatibilityEvidence)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Medium,
            "No likely package/sample compatibility evidence was detected.",
            "Baseline TEST-READINESS-004: add integration tests or build-together checks that keep the sample backend and reusable package compatible.",
            result.EvidencePath)];
    }
}
