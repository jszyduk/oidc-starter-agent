using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class KeycloakSetupExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-006";

    public override string Title => "No local Keycloak setup detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        if (!KeycloakSetupDetector.HasKeycloakSetup(snapshot))
        {
            return [Finding(
                FindingSeverity.Low,
                "No likely local Keycloak setup was found.",
                "Baseline BFF-CONFIG-003: include or document a local Keycloak setup, such as docker-compose configuration and realm import files, and clearly mark it as development-only.")];
        }

        if (KeycloakSetupDetector.HasDevelopmentOnlyLabeling(snapshot))
        {
            return [];
        }

        return [new AuditFinding(
            RuleId,
            "Local Keycloak setup is not clearly marked as development-only",
            FindingSeverity.Low,
            "A local Keycloak setup appears to exist, but no clear development-only warning was detected.",
            null,
            "Baseline BFF-CONFIG-003: clearly mark local Keycloak configuration as development-only and document that production deployments require environment-specific identity provider configuration.")];
    }
}
