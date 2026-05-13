using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class AntiforgeryMentionedRule : HardeningRuleBase
{
    private static readonly string[] Terms =
    [
        "antiforgery",
        "anti-forgery",
        "IAntiforgery",
        "UseAntiforgery"
    ];

    public override string RuleId => "HARDENING-004";

    public override string Title => "Antiforgery is configured";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files.Any(file => Terms.Any(term => file.Content.Contains(term, StringComparison.OrdinalIgnoreCase)));

        return exists
            ? []
            : [Finding(
                FindingSeverity.High,
                "No antiforgery-related code or configuration was found.",
                "Add antiforgery protection for cookie-backed BFF state-changing requests and document the frontend token flow.")];
    }
}
