using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class SampleRoleMappingDocumentationRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-024";

    public override string Title => "No sample role/claim mapping documentation detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = RoleMappingDocumentationDetector.Inspect(snapshot);
        if (result.HasDocumentation)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Low,
            "No likely documentation explaining sample role/claim mapping was detected.",
            "Baseline BFF-AUTHZ-003: document how sample/provider-specific roles or claims are mapped, including the extension point or example used by the starter.",
            result.EvidencePath)];
    }
}
