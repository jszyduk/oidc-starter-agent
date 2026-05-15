using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthenticationCookieHttpOnlyRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-011";

    public override string Title => "No explicit authentication cookie HttpOnly configuration detected";

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
