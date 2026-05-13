using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class KeycloakSetupExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-006";

    public override string Title => "Keycloak setup exists";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files.Any(file =>
            file.RelativePath.Contains("keycloak", StringComparison.OrdinalIgnoreCase)
            || file.Content.Contains("keycloak", StringComparison.OrdinalIgnoreCase)
            || IsDockerComposeFile(file) && file.Content.Contains("quay.io/keycloak", StringComparison.OrdinalIgnoreCase));

        return exists
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely local Keycloak setup was found.",
                "Include or document a local Keycloak setup, such as docker-compose configuration and realm import files.")];
    }

    private static bool IsDockerComposeFile(RepositoryFile file)
    {
        var fileName = Path.GetFileName(file.RelativePath);
        return fileName.StartsWith("docker-compose", StringComparison.OrdinalIgnoreCase);
    }
}
