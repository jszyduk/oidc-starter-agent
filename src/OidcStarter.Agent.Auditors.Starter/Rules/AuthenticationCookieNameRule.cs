using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthenticationCookieNameRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-020";

    public override string Title => "No explicit authentication cookie name configuration detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasExplicitAuthenticationCookieNameConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.Low,
                "No likely explicit authentication cookie name configuration was detected.",
                "Baseline BFF-COOKIE-004: configure an explicit authentication cookie name to make starter behavior clear and reduce collisions with host applications.")];
    }
}
