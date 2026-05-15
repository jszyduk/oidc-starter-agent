using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class LogoutClearsLocalSessionRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-010";

    public override string Title => "Logout does not appear to clear the local session";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var logoutExists = AspNetMvcEndpointDetector.ContainsControllerEndpoint(snapshot, "logout", "GET", "POST");
        if (!logoutExists)
        {
            return [];
        }

        return AspNetCookieSecurityDetector.LogoutClearsLocalCookieSession(snapshot)
            ? []
            : [Finding(
                FindingSeverity.High,
                "A logout endpoint exists, but no likely local application session or cookie sign-out was detected.",
                "Baseline BFF-ARCH-007: ensure logout clears the local application session/cookie, for example via HttpContext.SignOutAsync or equivalent local cookie scheme sign-out.")];
    }
}
