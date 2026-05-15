using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class ProductionHardeningDocumentationRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-016";

    public override string Title => "No production hardening documentation detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = ProductionHardeningDocumentationDetector.Inspect(snapshot);

        if (!result.HasDocumentationFiles || result.HasProductionHardeningNotes)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.Medium,
            "No likely production hardening notes were detected in README/docs.",
            "Baseline BFF-CONFIG-004: document production configuration assumptions and hardening caveats, including HTTPS, cookies, SameSite, CSRF/antiforgery, CORS, secrets, reverse proxy/forwarded headers, and development-only identity provider setup where applicable.")];
    }
}
