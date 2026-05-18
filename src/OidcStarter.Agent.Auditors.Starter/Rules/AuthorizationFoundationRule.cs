using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthorizationFoundationRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-022";

    public override string Title => "No clear authorization foundation detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = AspNetAuthorizationDetector.Inspect(snapshot);
        if (result.HasFoundation)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Medium,
            "No likely authorization foundation was detected in the starter package or supporting sample.",
            "Baseline BFF-AUTHZ-001: provide a visible authorization foundation, such as AddAuthorization configuration, policies or role/claim mapping extension points, and at least one protected endpoint or sample demonstrating authorization usage.",
            result.EvidencePath)];
    }
}
