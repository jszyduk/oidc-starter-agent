using OidcStarter.Agent.Auditors.Starter.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class UnsafeHttpMethodsAntiforgeryCoverageRule : HardeningRuleBase
{
    public override string RuleId => "HARDENING-021";

    public override string Title => "Unsafe BFF endpoints may not be covered by antiforgery protection";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        var result = AspNetMvcUnsafeEndpointDetector.Inspect(snapshot);
        if (!result.HasUncoveredEndpoints)
        {
            return [];
        }

        var examples = string.Join(
            ", ",
            result.UncoveredEndpoints
                .Take(3)
                .Select(endpoint => endpoint.DisplayName));
        var ignoredCount = result.UncoveredEndpoints.Count(endpoint => endpoint.IsIgnored);
        var ignoredPhrase = ignoredCount > 0
            ? $" {ignoredCount} endpoint(s) appear to opt out with IgnoreAntiforgeryToken."
            : string.Empty;

        return [Finding(
            FindingSeverity.High,
            $"One or more unsafe MVC endpoints were detected without likely antiforgery coverage. Examples: {examples}.{ignoredPhrase}",
            "Baseline BFF-CSRF-004: protect unsafe browser-to-BFF endpoints such as POST, PUT, PATCH, and DELETE with antiforgery validation, for example via ValidateAntiForgeryToken, AutoValidateAntiforgeryToken, or a global MVC antiforgery filter.",
            result.UncoveredEndpoints[0].FilePath)];
    }
}
