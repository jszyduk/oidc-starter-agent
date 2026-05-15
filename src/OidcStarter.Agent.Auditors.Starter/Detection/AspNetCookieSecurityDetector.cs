using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AspNetCookieSecurityDetector
{
    public static bool HasHttpOnlyCookieConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => HttpOnlyRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool HasSecureCookieConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => SecurePolicyRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool HasSameSiteCookieConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => HasSameSiteAssignment(RemoveComments(file.Content)));
    }

    public static bool HasExplicitAuthenticationCookieNameConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => HasCookieNameAssignment(PrepareCodeForCookieMatching(file.Content)));
    }

    public static bool HasExplicitCookieLifetimeConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => HasCookieLifetimeAssignment(PrepareCodeForCookieMatching(file.Content)));
    }

    public static bool HasExplicitSlidingExpirationConfiguration(RepositorySnapshot snapshot)
    {
        return StarterCookieConfigurationFiles(snapshot).Any(file => HasSlidingExpirationAssignment(PrepareCodeForCookieMatching(file.Content)));
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
        return CSharpFiles(snapshot).Where(StarterRepositoryLayoutDetector.IsProductionStarterCodeFile);
    }

    private static IEnumerable<RepositoryFile> StarterCookieConfigurationFiles(RepositorySnapshot snapshot)
    {
        var productionFiles = ProductionCSharpFiles(snapshot).ToList();
        var packageFiles = productionFiles
            .Where(StarterRepositoryLayoutDetector.IsBffPackageFile)
            .ToList();

        if (packageFiles.Count > 0)
        {
            return packageFiles;
        }

        return productionFiles.Where(StarterRepositoryLayoutDetector.IsSampleBackendFile);
    }

    private static string RemoveComments(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        return LineCommentRegex().Replace(withoutBlockComments, string.Empty);
    }

    private static string PrepareCodeForCookieMatching(string content)
    {
        var withoutComments = RemoveComments(content);
        var withoutRawStrings = RawStringLiteralRegex().Replace(withoutComments, "STRING_LITERAL");
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(withoutRawStrings, match => IsEmptyVerbatimStringLiteral(match.Value) ? "EMPTY_STRING_LITERAL" : "STRING_LITERAL");
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, match => IsEmptyRegularStringLiteral(match.Value) ? "EMPTY_STRING_LITERAL" : "STRING_LITERAL");
    }

    private static bool HasSameSiteAssignment(string content)
    {
        return SameSiteAssignmentRegex()
            .Matches(content)
            .Any(match => IsValidSameSiteValue(match.Groups["value"].Value));
    }

    private static bool IsValidSameSiteValue(string value)
    {
        var trimmedValue = value.Trim();

        return SameSiteModeValueRegex().IsMatch(trimmedValue)
            || CookieSameSiteSettingRegex().IsMatch(trimmedValue);
    }

    private static bool HasCookieLifetimeAssignment(string content)
    {
        return ExplicitCookieLifetimeRegex().IsMatch(content)
            || GenericCookieLifetimeRegex()
                .Matches(content)
                .Any(match => HasNearbyAuthenticationCookieContext(content, match.Index));
    }

    private static bool HasCookieNameAssignment(string content)
    {
        return CookieNameAssignmentRegex()
            .Matches(content)
            .Any(match => IsValidCookieNameValue(match.Groups["value"].Value)
                && HasNearbyAuthenticationCookieContext(content, match.Index));
    }

    private static bool HasSlidingExpirationAssignment(string content)
    {
        return ExplicitSlidingExpirationRegex().IsMatch(content)
            || GenericSlidingExpirationRegex()
                .Matches(content)
                .Any(match => HasNearbyAuthenticationCookieContext(content, match.Index));
    }

    private static bool HasNearbyAuthenticationCookieContext(string content, int matchIndex)
    {
        const int WindowSize = 400;

        var start = Math.Max(0, matchIndex - WindowSize);
        var length = Math.Min(content.Length - start, WindowSize * 2);
        var window = content.Substring(start, length);

        return AuthenticationCookieContextRegex().IsMatch(window);
    }

    private static bool IsValidCookieNameValue(string value)
    {
        var trimmedValue = value.Trim();

        return trimmedValue.Equals("STRING_LITERAL", StringComparison.Ordinal)
            || CookieNameSettingRegex().IsMatch(trimmedValue);
    }

    private static bool IsEmptyVerbatimStringLiteral(string value)
    {
        var normalizedValue = value;
        if (normalizedValue.StartsWith("$@", StringComparison.Ordinal)
            || normalizedValue.StartsWith("@$", StringComparison.Ordinal))
        {
            normalizedValue = normalizedValue[2..];
        }
        else if (normalizedValue.StartsWith('@'))
        {
            normalizedValue = normalizedValue[1..];
        }

        return normalizedValue.Equals("\"\"", StringComparison.Ordinal);
    }

    private static bool IsEmptyRegularStringLiteral(string value)
    {
        var normalizedValue = value.StartsWith('$')
            ? value[1..]
            : value;

        return normalizedValue.Equals("\"\"", StringComparison.Ordinal);
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

    [GeneratedRegex(@"\b(?:new\s+CookieBuilder\s*\{[^}]*\bSameSite|(?:\b\w+|\))?\.?(?:Cookie|CorrelationCookie|NonceCookie)\.SameSite)\s*=\s*(?<value>[^,;}\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex SameSiteAssignmentRegex();

    [GeneratedRegex(@"\b(?:(?:options|cookieOptions|authCookieOptions|cookieAuthenticationOptions)\.Cookie\.Name|Cookie\.Name|Name)\s*=\s*(?<value>[^,;}\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CookieNameAssignmentRegex();

    [GeneratedRegex(@"^(?:\w+\.)*CookieName$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CookieNameSettingRegex();

    [GeneratedRegex(@"\b(?:options|cookieOptions|authCookieOptions|cookieAuthenticationOptions)\.ExpireTimeSpan\s*=\s*[^,;}\r\n]+|\b(?:options|cookieOptions|authCookieOptions|cookieAuthenticationOptions)\.Cookie\.(?:MaxAge|Expiration)\s*=\s*[^,;}\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitCookieLifetimeRegex();

    [GeneratedRegex(@"\b(?:ExpireTimeSpan|MaxAge)\s*=\s*[^,;}\r\n]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GenericCookieLifetimeRegex();

    [GeneratedRegex(@"\b(?:options|cookieOptions|authCookieOptions|cookieAuthenticationOptions)\.SlidingExpiration\s*=\s*(?:true|false|(?:\w+\.)*(?:CookieSlidingExpiration|SlidingExpiration))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitSlidingExpirationRegex();

    [GeneratedRegex(@"\bSlidingExpiration\s*=\s*(?:true|false|(?:\w+\.)*(?:CookieSlidingExpiration|SlidingExpiration))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GenericSlidingExpirationRegex();

    [GeneratedRegex(@"\b(?:AddCookie|AddAuthentication|CookieAuthenticationOptions|CookieBuilder|ConfigureApplicationCookie|AuthenticationScheme|CookieAuthenticationDefaults)\b|\boptions\.(?:ExpireTimeSpan|SlidingExpiration)\b|\boptions\.Cookie\.(?:HttpOnly|SecurePolicy|SameSite)\b|\bCookie\.(?:HttpOnly|SecurePolicy|SameSite)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthenticationCookieContextRegex();

    [GeneratedRegex(@"^SameSiteMode\.(?:Strict|Lax|None)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SameSiteModeValueRegex();

    [GeneratedRegex(@"^(?:\w+\.)*CookieSameSite$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CookieSameSiteSettingRegex();

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

    [GeneratedRegex(@"(?:\$@|@\$|@)""(?:""""|[^""])*""", RegexOptions.CultureInvariant)]
    private static partial Regex VerbatimStringLiteralRegex();

    [GeneratedRegex(@"\$?""(?:\\.|[^""\\])*""", RegexOptions.CultureInvariant)]
    private static partial Regex RegularStringLiteralRegex();

    [GeneratedRegex(@"\$*""""""[\s\S]*?""""""", RegexOptions.CultureInvariant)]
    private static partial Regex RawStringLiteralRegex();
}
