using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class AuthenticationCookieHttpOnlyRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-011";

    public override string Title => "Authentication cookie is HttpOnly";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasHttpOnlyCookieConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely HttpOnly authentication cookie configuration was detected.",
                "Baseline BFF-COOKIE-001: configure authentication cookies as HttpOnly or document the safe framework default explicitly.")];
    }
}
