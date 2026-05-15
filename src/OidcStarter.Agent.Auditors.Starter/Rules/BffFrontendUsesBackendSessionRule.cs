using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class BffFrontendUsesBackendSessionRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-015";

    public override string Title => "BFF frontend may be handling tokens instead of relying on backend session";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return BffFrontendSessionDetector.GetSuspiciousBffTokenHandlingFiles(snapshot)
            .Select(file => Finding(
                FindingSeverity.High,
                "Suspicious browser token or bearer-auth handling was detected in frontend code that appears to participate in BFF mode.",
                "Baseline BFF-ARCH-002: in BFF mode, the browser frontend should rely on backend session/cookie semantics and call backend auth/session endpoints instead of handling OAuth access or refresh tokens directly.",
                file.RelativePath))
            .ToList();
    }
}
