using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthenticationCookieLifetimeRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-018";

    public override string Title => "No explicit authentication cookie lifetime configuration detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasExplicitCookieLifetimeConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely explicit authentication cookie lifetime/session duration configuration was detected.",
                "Baseline BFF-COOKIE-005: configure the authentication cookie lifetime or session duration explicitly so starter consumers do not inherit unclear defaults.")];
    }
}
