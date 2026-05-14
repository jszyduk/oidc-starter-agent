using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class AuthenticationCookieSameSiteRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-013";

    public override string Title => "Authentication cookie SameSite is configured";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetCookieSecurityDetector.HasSameSiteCookieConfiguration(snapshot)
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely authentication cookie SameSite configuration was detected.",
                "Baseline BFF-COOKIE-003: configure SameSite intentionally and document the choice, considering CSRF and OIDC redirect compatibility.")];
    }
}
