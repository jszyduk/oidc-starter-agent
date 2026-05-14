using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class LoginEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-001";

    public override string Title => "No likely MVC login endpoint detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = AspNetMvcEndpointDetector.ContainsControllerEndpoint(snapshot, "login", "GET", "POST");

        return exists
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely login endpoint was found in backend C# files.",
                "Expose and test a BFF login endpoint that initiates the OpenID Connect challenge.")];
    }
}
