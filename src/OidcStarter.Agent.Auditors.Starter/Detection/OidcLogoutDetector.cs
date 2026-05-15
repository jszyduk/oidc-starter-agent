using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class OidcLogoutDetector
{
    private static readonly string[] DocumentationProviderSignals =
    [
        "identity provider",
        "idp",
        "oidc provider",
        "openid connect provider",
        "upstream session",
        "provider session",
        "remote sign-out"
    ];

    private static readonly string[] DocumentationLocalOrRemoteSignals =
    [
        "local session",
        "local cookie",
        "application cookie",
        "post logout redirect",
        "post-logout redirect",
        "remote sign-out",
        "signedoutcallbackpath"
    ];

    public static bool AccountsForIdentityProviderLogout(RepositorySnapshot snapshot)
    {
        return HasOidcSignOutImplementation(snapshot) || HasOidcLogoutDocumentation(snapshot);
    }

    public static bool HasProductionLogoutEndpoint(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot)
            .Select(file => RemoveComments(file.Content))
            .Any(ContainsLikelyLogoutEndpoint);
    }

    public static bool HasOidcSignOutImplementation(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot)
            .Select(file => RemoveComments(file.Content))
            .Any(content => HasOidcSignOutInLogoutAction(content)
                || RedirectToIdentityProviderForSignOutRegex().IsMatch(content));
    }

    public static bool HasOidcLogoutDocumentation(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(IsDocumentationFile)
            .Select(file => StripMarkdownCodeBlocks(file.Content))
            .SelectMany(SplitIntoParagraphs)
            .Any(HasMeaningfulLogoutDocumentation);
    }

    private static IEnumerable<RepositoryFile> ProductionCSharpFiles(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Where(StarterRepositoryLayoutDetector.IsProductionStarterCodeFile);
    }

    private static bool HasOidcSignOutInLogoutAction(string content)
    {
        return GetLikelyLogoutActionBodies(content)
            .Any(body => LogoutSignOutRegex().IsMatch(body)
                && OpenIdConnectSchemeRegex().IsMatch(body));
    }

    private static IEnumerable<string> GetLikelyLogoutActionBodies(string content)
    {
        foreach (Match match in MethodRegex().Matches(content))
        {
            var methodName = match.Groups["name"].Value;
            var beforeMethod = content[..match.Index];
            var previousCloseBrace = beforeMethod.LastIndexOf('}');
            var attributeContext = previousCloseBrace >= 0
                ? beforeMethod[(previousCloseBrace + 1)..]
                : beforeMethod;

            if (!methodName.Equals("Logout", StringComparison.OrdinalIgnoreCase)
                && !methodName.Equals("LogoutAsync", StringComparison.OrdinalIgnoreCase)
                && !LogoutRouteRegex().IsMatch(attributeContext))
            {
                continue;
            }

            var bodyStart = content.IndexOf('{', match.Index);
            if (bodyStart < 0)
            {
                continue;
            }

            var bodyEnd = FindMatchingBrace(content, bodyStart);
            if (bodyEnd > bodyStart)
            {
                yield return content.Substring(bodyStart, bodyEnd - bodyStart + 1);
            }
        }
    }

    private static int FindMatchingBrace(string content, int openBraceIndex)
    {
        var depth = 0;

        for (var index = openBraceIndex; index < content.Length; index++)
        {
            if (content[index] == '{')
            {
                depth++;
            }
            else if (content[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
    }

    private static bool ContainsLikelyLogoutEndpoint(string content)
    {
        return GetLikelyLogoutActionBodies(content).Any();
    }

    private static bool IsDocumentationFile(RepositoryFile file)
    {
        var path = file.RelativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(path);

        if (!fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IsIgnoredPath(path) || IsInternalAnalyzerDocument(path) || IsLikelyGeneratedReport(path))
        {
            return false;
        }

        return path.Equals("README.md", StringComparison.OrdinalIgnoreCase)
            || !path.Contains('/', StringComparison.Ordinal)
            || path.StartsWith("docs/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasMeaningfulLogoutDocumentation(string paragraph)
    {
        return LogoutDocumentationTermRegex().IsMatch(paragraph)
            && DocumentationProviderSignals.Any(signal => ContainsSignal(paragraph, signal))
            && DocumentationLocalOrRemoteSignals.Any(signal => ContainsSignal(paragraph, signal));
    }

    private static IEnumerable<string> SplitIntoParagraphs(string content)
    {
        return ParagraphSplitRegex()
            .Split(content)
            .Where(paragraph => !string.IsNullOrWhiteSpace(paragraph));
    }

    private static bool IsIgnoredPath(string path)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        return segments.Any(segment =>
            segment.Equals("sample-output", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("reports", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("bin", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("obj", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("node_modules", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsInternalAnalyzerDocument(string path)
    {
        var fileName = Path.GetFileName(path);
        return fileName.StartsWith("security-baseline", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyGeneratedReport(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);

        return fileName.Equals("audit-report", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("-report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("_report", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsSignal(string content, string signal)
    {
        return Regex.IsMatch(
            content,
            $@"(?<![a-z0-9]){Regex.Escape(signal)}(?![a-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static string RemoveComments(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        return LineCommentRegex().Replace(withoutBlockComments, string.Empty);
    }

    private static string StripMarkdownCodeBlocks(string content)
    {
        var withoutBacktickFences = BacktickFenceRegex().Replace(content, string.Empty);
        var withoutTildeFences = TildeFenceRegex().Replace(withoutBacktickFences, string.Empty);
        return IndentedCodeBlockRegex().Replace(withoutTildeFences, string.Empty);
    }

    [GeneratedRegex(@"\[\s*(?:HttpGet|HttpPost|Route)(?:Attribute)?\s*\(\s*[""'](?:[^""']*/)?logout[""'][^\)]*\)\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutRouteRegex();

    [GeneratedRegex(@"\bpublic\s+(?:async\s+)?[\w<>,\s\[\]\?\.]+\s+(?<name>\w+)\s*\([^)]*\)\s*(?:where\s+[^{]+)?\{", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MethodRegex();

    [GeneratedRegex(@"\b(?:HttpContext\.)?SignOutAsync\s*\(|\breturn\s+SignOut\s*\(|\bnew\s+SignOutResult\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutSignOutRegex();

    [GeneratedRegex(@"\bOpenIdConnectDefaults\.AuthenticationScheme\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpenIdConnectSchemeRegex();

    [GeneratedRegex(@"\bOnRedirectToIdentityProviderForSignOut\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RedirectToIdentityProviderForSignOutRegex();

    [GeneratedRegex(@"\b(?:logout|sign-out|sign out)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutDocumentationTermRegex();

    [GeneratedRegex(@"\r?\n\s*\r?\n", RegexOptions.CultureInvariant)]
    private static partial Regex ParagraphSplitRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"```.*?```", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BacktickFenceRegex();

    [GeneratedRegex(@"~~~.*?~~~", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TildeFenceRegex();

    [GeneratedRegex(@"^(?: {4}|\t).*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex IndentedCodeBlockRegex();
}
