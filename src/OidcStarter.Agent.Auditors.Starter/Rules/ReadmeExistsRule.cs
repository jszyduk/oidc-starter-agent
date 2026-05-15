using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class ReadmeExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-008";

    public override string Title => "README.md is missing";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files.Any(file => file.RelativePath.Equals("README.md", StringComparison.OrdinalIgnoreCase));

        return exists
            ? []
            : [Finding(
                FindingSeverity.Low,
                "The repository root README.md file was not found.",
                "Add a README.md that explains the BFF starter, setup steps, authentication flow, and security expectations.")];
    }
}
