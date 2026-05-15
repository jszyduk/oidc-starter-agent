using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AspNetMvcEndpointDetector
{
    public static bool ContainsControllerEndpoint(
        RepositorySnapshot snapshot,
        string endpointName,
        params string[] httpMethods)
    {
        var allowedHttpMethods = httpMethods
            .Select(method => method.ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Any(file => ContainsRouteAttribute(file.Content, endpointName, allowedHttpMethods)
                || ContainsActionNameFallback(file.Content, endpointName));
    }

    private static bool ContainsRouteAttribute(
        string content,
        string endpointName,
        IReadOnlySet<string> allowedHttpMethods)
    {
        foreach (Match match in RouteAttributeRegex().Matches(content))
        {
            var attributeName = match.Groups["attribute"].Value;
            var route = match.Groups["route"].Value;

            if (string.IsNullOrWhiteSpace(route))
            {
                continue;
            }

            if (!RouteTargetsEndpoint(route, endpointName))
            {
                continue;
            }

            if (attributeName.Equals("Route", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var method = attributeName["Http".Length..].ToUpperInvariant();
            if (allowedHttpMethods.Count == 0 || allowedHttpMethods.Contains(method))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsActionNameFallback(string content, string endpointName)
    {
        if (!LooksLikeControllerFile(content))
        {
            return false;
        }

        var escapedEndpointName = Regex.Escape(endpointName);
        var pattern = $@"\bpublic\s+(?:async\s+)?[\w<>,\s\[\]\?\.]+\s+{escapedEndpointName}(?:Async)?\s*\(";

        return Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static bool LooksLikeControllerFile(string content)
    {
        return content.Contains("[ApiController]", StringComparison.OrdinalIgnoreCase)
            || content.Contains("ControllerBase", StringComparison.OrdinalIgnoreCase)
            || ControllerClassRegex().IsMatch(content);
    }

    private static bool RouteTargetsEndpoint(string route, string endpointName)
    {
        var normalizedRoute = route
            .Trim()
            .TrimStart('~')
            .Trim('/');

        return normalizedRoute.Equals(endpointName, StringComparison.OrdinalIgnoreCase)
            || normalizedRoute.EndsWith("/" + endpointName, StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"\[\s*(?<attribute>HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)(?:Attribute)?\s*\(\s*[""'](?<route>[^""']+)[""'][^\)]*\)\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RouteAttributeRegex();

    [GeneratedRegex(@"\bclass\s+\w*Controller\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ControllerClassRegex();
}
