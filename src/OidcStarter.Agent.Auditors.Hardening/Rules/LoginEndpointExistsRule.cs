using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class LoginEndpointExistsRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-001";

    public override string Title => "Login endpoint exists";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Any(file => ContainsAny(file.Content, "\"/login\"", "'/login'", " login", "Login"));

        return exists
            ? []
            : [Finding(
                FindingSeverity.High,
                "No likely login endpoint was found in backend C# files.",
                "Expose and test a BFF login endpoint that initiates the OpenID Connect challenge.")];
    }

    private static bool ContainsAny(string content, params string[] terms)
    {
        return terms.Any(term => content.Contains(term, StringComparison.OrdinalIgnoreCase));
    }
}
