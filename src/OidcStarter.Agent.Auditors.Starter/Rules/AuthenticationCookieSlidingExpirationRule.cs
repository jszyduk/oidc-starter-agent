using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class AuthenticationCookieSlidingExpirationRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-019";

    public override string Title => "No explicit authentication cookie sliding expiration decision detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasExplicitSlidingExpirationConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.Low,
                "No likely explicit authentication cookie sliding expiration setting was detected.",
                "Baseline BFF-COOKIE-006: configure sliding expiration explicitly as true or false so the session renewal behavior is intentional.")];
    }
}
