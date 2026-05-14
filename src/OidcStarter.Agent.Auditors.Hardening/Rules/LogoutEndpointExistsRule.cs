using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class LogoutEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-002";

    public override string Title => "No likely MVC logout endpoint detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = AspNetMvcEndpointDetector.ContainsControllerEndpoint(snapshot, "logout", "GET", "POST");

        return exists
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely logout endpoint was found in backend C# files.",
                "Expose and test a BFF logout endpoint that clears the local auth cookie and signs out of the identity provider.")];
    }
}
