using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class BffAntiforgeryFlowRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-004";

    public override string Title => "No likely complete BFF antiforgery flow detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetAntiforgeryDetector.HasMeaningfulBffAntiforgeryFlow(snapshot)
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely complete browser-to-BFF antiforgery flow was detected.",
                "Baseline BFF-CSRF-002: ensure a browser-to-BFF antiforgery flow exists, including backend antiforgery configuration, token issuing/storage, and frontend/header usage or documented header convention.")];
    }
}
