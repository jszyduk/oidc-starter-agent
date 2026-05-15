using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthenticationCookieSecurePolicyRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-012";

    public override string Title => "No explicit authentication cookie SecurePolicy configuration detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasSecureCookieConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely authentication cookie SecurePolicy configuration was detected.",
                "Baseline BFF-COOKIE-002: configure authentication cookie SecurePolicy intentionally, preferably CookieSecurePolicy.Always for production.")];
    }
}
