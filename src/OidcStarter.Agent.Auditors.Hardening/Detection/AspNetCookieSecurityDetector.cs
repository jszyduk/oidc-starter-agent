using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Detection;

public static partial class AspNetCookieSecurityDetector
{
    public static bool HasHttpOnlyCookieConfiguration(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot).Any(file => HttpOnlyRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool HasSecureCookieConfiguration(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot).Any(file => SecurePolicyRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool HasSameSiteCookieConfiguration(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot).Any(file => SameSiteRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool LogoutClearsLocalCookieSession(RepositorySnapshot snapshot)
    {
        return CSharpFiles(snapshot)
            .Select(file => RemoveComments(file.Content))
            .SelectMany(GetLikelyLogoutActionBodies)
            .Any(body => SignOutRegex().IsMatch(body));
    }

    private static IEnumerable<RepositoryFile> CSharpFiles(RepositorySnapshot snapshot)
    {
        return snapshot.Files.Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<RepositoryFile> ProductionCSharpFiles(RepositorySnapshot snapshot)
    {
        return CSharpFiles(snapshot).Where(file => !IsTestFile(file.RelativePath));
    }

    private static bool IsTestFile(string relativePath)
    {
        var normalizedPath = relativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalizedPath);

        return normalizedPath.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains(".Tests", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static string RemoveComments(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        return LineCommentRegex().Replace(withoutBlockComments, string.Empty);
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

    [GeneratedRegex(@"\bnew\s+CookieBuilder\s*\{[^}]*\bHttpOnly\s*=\s*true\b|(?:\b\w+|\))?\.?Cookie\.HttpOnly\s*=\s*true\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex HttpOnlyRegex();

    [GeneratedRegex(@"\bnew\s+CookieBuilder\s*\{[^}]*\bSecurePolicy\s*=\s*CookieSecurePolicy\.(?:Always|SameAsRequest)\b|(?:\b\w+|\))?\.?Cookie\.SecurePolicy\s*=\s*CookieSecurePolicy\.(?:Always|SameAsRequest)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SecurePolicyRegex();

    [GeneratedRegex(@"\bnew\s+CookieBuilder\s*\{[^}]*\bSameSite\s*=\s*SameSiteMode\.(?:Strict|Lax|None)\b|(?:\b\w+|\))?\.?Cookie\.SameSite\s*=\s*SameSiteMode\.(?:Strict|Lax|None)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SameSiteRegex();

    [GeneratedRegex(@"\[\s*(?:HttpGet|HttpPost|Route)(?:Attribute)?\s*\(\s*[""'](?:[^""']*/)?logout[""'][^\)]*\)\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutRouteRegex();

    [GeneratedRegex(@"\bpublic\s+(?:async\s+)?[\w<>,\s\[\]\?\.]+\s+(?<name>\w+)\s*\([^)]*\)\s*(?:where\s+[^{]+)?\{", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MethodRegex();

    [GeneratedRegex(@"\b(?:HttpContext\.)?SignOutAsync\s*\(|\breturn\s+SignOut\s*\(|\bnew\s+SignOutResult\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SignOutRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();
}
