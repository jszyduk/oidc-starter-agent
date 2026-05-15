using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class OidcIdentityProviderLogoutAwarenessRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-017";

    public override string Title => "Logout does not appear to account for identity-provider sign-out";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var logoutExists = OidcLogoutDetector.HasProductionLogoutEndpoint(snapshot);
        if (!logoutExists)
        {
            return [];
        }

        return OidcLogoutDetector.AccountsForIdentityProviderLogout(snapshot)
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "A logout endpoint appears to exist, but no likely identity-provider sign-out implementation or documented local-vs-IdP logout decision was detected.",
                "Baseline BFF-ARCH-008: account for identity-provider sign-out where applicable, either by implementing OIDC provider sign-out or by documenting the local-vs-provider logout behavior and production expectations.")];
    }
}
