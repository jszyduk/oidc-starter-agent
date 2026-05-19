using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class MinimalFrontendClaimsExposureRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-029";

    public override string Title => "Frontend identity endpoint may expose excessive claims or tokens";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = FrontendClaimsExposureDetector.Inspect(snapshot);
        if (!result.HasRiskyExposure)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Medium,
            "A likely frontend identity/session endpoint appears to expose raw claims, identity objects, authentication properties, or tokens.",
            "Baseline BFF-AUTHZ-005: expose only minimal, intentional frontend identity data from /me or current-user endpoints, such as authentication state and selected public claims, and avoid returning raw claims, tokens, or ClaimsPrincipal objects.",
            result.EvidencePath)];
    }
}
