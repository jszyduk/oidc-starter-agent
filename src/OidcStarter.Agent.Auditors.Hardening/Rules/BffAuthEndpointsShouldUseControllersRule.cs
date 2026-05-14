using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed partial class BffAuthEndpointsShouldUseControllersRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-009";

    public override string Title => "BFF auth endpoints appear to use Minimal API mappings";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Where(file => MinimalApiAuthEndpointRegex().IsMatch(file.Content))
            .Select(file => Finding(
                FindingSeverity.Medium,
                "A BFF auth endpoint appears to be implemented using Minimal API route mapping.",
                "Implement BFF auth endpoints as ASP.NET Core MVC controller actions to keep the reference implementation explicit, testable and consistent.",
                file.RelativePath))
            .ToList();
    }

    [GeneratedRegex(@"\b(?:app|endpoints|group)\.Map(?:Get|Post)\s*\(\s*[""'](?:/)?(?:api/auth/)?(?:me|login|logout)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MinimalApiAuthEndpointRegex();
}
