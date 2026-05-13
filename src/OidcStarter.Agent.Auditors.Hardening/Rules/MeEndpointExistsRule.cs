using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class MeEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-003";

    public override string Title => "Current user endpoint exists";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Any(file => file.Content.Contains("/me", StringComparison.OrdinalIgnoreCase));

        return exists
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely current-user endpoint was found in backend C# files.",
                "Expose and test a BFF '/me' endpoint or equivalent current-user endpoint for frontend session state.")];
    }
}
