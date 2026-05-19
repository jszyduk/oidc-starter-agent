using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class BffAuthorizationCodeFlowRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-030";

    public override string Title => "BFF OIDC flow may not be explicitly configured for Authorization Code";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = OidcFlowDetector.Inspect(snapshot);
        if (result.UsesAuthorizationCodeFlow)
        {
            return [];
        }

        return [Finding(
            FindingSeverity.High,
            "No explicit BFF Authorization Code flow configuration was detected, or risky implicit/hybrid response type evidence was found.",
            "Baseline OIDC-FLOW-001: configure the BFF OpenID Connect client to use Authorization Code flow, and avoid implicit or hybrid response types in server-side BFF authentication.",
            result.EvidencePath)];
    }
}
