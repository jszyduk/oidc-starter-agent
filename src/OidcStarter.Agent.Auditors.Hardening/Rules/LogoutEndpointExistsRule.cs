using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class LogoutEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-002";

    public override string Title => "Logout endpoint exists";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Any(file => file.Content.Contains("/logout", StringComparison.OrdinalIgnoreCase)
                || file.Content.Contains("Logout", StringComparison.OrdinalIgnoreCase));

        return exists
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely logout endpoint was found in backend C# files.",
                "Expose and test a BFF logout endpoint that clears the local auth cookie and signs out of the identity provider.")];
    }
}
