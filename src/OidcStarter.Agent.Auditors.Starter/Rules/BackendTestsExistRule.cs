using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class BackendTestsExistRule : HardeningRuleBase
{
    private static readonly string[] TestTerms =
    [
        "xunit",
        "nunit",
        "mstest",
        "Microsoft.NET.Test.Sdk"
    ];

    public override string RuleId => "HARDENING-007";

    public override string Title => "No likely backend/package tests detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var exists = snapshot.Files.Any(file =>
            file.RelativePath.Contains("test", StringComparison.OrdinalIgnoreCase)
            && (file.RelativePath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
                || TestTerms.Any(term => file.Content.Contains(term, StringComparison.OrdinalIgnoreCase))));

        return exists
            ? []
            : [Finding(
                FindingSeverity.Medium,
                "No likely backend or package tests were found.",
                "Add tests for the backend package and security-sensitive BFF behavior using xUnit, NUnit, or MSTest.")];
    }
}
