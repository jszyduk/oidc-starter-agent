using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class RoleClaimMappingTestCoverageRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-023";

    public override string Title => "No explicit and tested role/claim mapping detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = RoleClaimMappingDetector.Inspect(snapshot);
        if (result.HasExplicitAndTestedMapping)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Medium,
            "No likely explicit role/claim mapping implementation or corresponding test evidence was detected.",
            "Baseline BFF-AUTHZ-002: provide explicit role/claim mapping behavior or extension points and tests that verify provider-specific roles/claims are mapped as intended.",
            result.EvidencePath)];
    }
}
