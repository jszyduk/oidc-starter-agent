using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class MeEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-003";

    public override string Title => "Current user endpoint exists";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = AspNetMvcEndpointDetector.ContainsControllerEndpoint(snapshot, "me", "GET");

        return exists
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely current-user endpoint was found in backend C# files.",
                "Expose and test a BFF '/me' endpoint or equivalent current-user endpoint for frontend session state.")];
    }
}
