using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AuthEndpointBehaviorTestDetector
{
    public static AuthEndpointBehaviorTestResult Inspect(RepositorySnapshot snapshot)
    {
        var result = new BehaviorSignals();

        foreach (var file in snapshot.Files.Where(IsEligibleTestFile))
        {
            var content = StripCommentsAndRawStrings(file.Content);
            var identifierContent = StripStringLiterals(content);
            var identifierText = $"{Path.GetFileNameWithoutExtension(NormalizePath(file.RelativePath))}\n{identifierContent}";
            var codeWithoutStrings = StripStringLiterals(content);

            AddEvidence(
                result,
                file.RelativePath,
                HasLoginEvidence(identifierText, content, codeWithoutStrings),
                HasLogoutEvidence(identifierText, content, codeWithoutStrings),
                HasMeEvidence(identifierText, content, codeWithoutStrings));
        }

        return new AuthEndpointBehaviorTestResult(
            result.HasLogin,
            result.HasLogout,
            result.HasMe,
            result.FirstEvidencePath);
    }

    private static void AddEvidence(
        BehaviorSignals result,
        string relativePath,
        bool hasLogin,
        bool hasLogout,
        bool hasMe)
    {
        result.HasLogin |= hasLogin;
        result.HasLogout |= hasLogout;
        result.HasMe |= hasMe;

        if ((hasLogin || hasLogout || hasMe) && result.FirstEvidencePath is null)
        {
            result.FirstEvidencePath = relativePath;
        }
    }

    private static bool HasLoginEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = LoginIdentifierRegex().IsMatch(identifierText);
        var hasRoute = LoginRouteRegex().IsMatch(content);
        var hasBehaviorEvidence = hasRoute || LoginBehaviorRegex().IsMatch(codeWithoutStrings);
        var hasRouteWithAssertion = hasRoute && LoginAssertionRegex().IsMatch(codeWithoutStrings);

        return (hasIdentifier && hasBehaviorEvidence) || hasRouteWithAssertion;
    }

    private static bool HasLogoutEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = LogoutIdentifierRegex().IsMatch(identifierText);
        var hasRoute = LogoutRouteRegex().IsMatch(content);
        var hasBehaviorEvidence = hasRoute || LogoutBehaviorRegex().IsMatch(codeWithoutStrings);
        var hasRouteWithAssertion = hasRoute && LogoutAssertionRegex().IsMatch(codeWithoutStrings);

        return (hasIdentifier && hasBehaviorEvidence) || hasRouteWithAssertion;
    }

    private static bool HasMeEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = MeIdentifierRegex().IsMatch(identifierText);
        var hasRoute = MeRouteRegex().IsMatch(content);
        var hasBehaviorEvidence = hasRoute || MeBehaviorRegex().IsMatch(codeWithoutStrings);
        var hasRouteWithAssertion = hasRoute && MeAssertionRegex().IsMatch(codeWithoutStrings);

        return (hasIdentifier && hasBehaviorEvidence) || hasRouteWithAssertion;
    }

    private static bool IsEligibleTestFile(RepositoryFile file)
    {
        if (!file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = NormalizePath(file.RelativePath);
        if (path.Contains("/bin/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/node_modules/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/reports/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/sample-output/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("audit-report", StringComparison.OrdinalIgnoreCase)
            || StarterRepositoryLayoutDetector.IsSampleBackendFile(file)
            || StarterRepositoryLayoutDetector.IsBffPackageFile(file))
        {
            return false;
        }

        if (StarterRepositoryLayoutDetector.IsBffTestsFile(file))
        {
            return true;
        }

        var fileName = Path.GetFileName(path);
        var isClearlyTestFile = file.Content.Contains("[Fact]", StringComparison.OrdinalIgnoreCase)
            || file.Content.Contains("[Theory]", StringComparison.OrdinalIgnoreCase)
            || file.Content.Contains("[Test]", StringComparison.OrdinalIgnoreCase)
            || file.Content.Contains("Assert.", StringComparison.OrdinalIgnoreCase)
            || path.Contains(".Tests/", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);

        if (!isClearlyTestFile)
        {
            return false;
        }

        return path.StartsWith("tests/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || path.Contains(".Tests/", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static string StripCommentsAndRawStrings(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        return RawStringLiteralRegex().Replace(withoutLineComments, "RAW_STRING_LITERAL");
    }

    private static string StripStringLiterals(string content)
    {
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(content, "STRING_LITERAL");
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, "STRING_LITERAL");
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    [GeneratedRegex(@"\b(?:Login|SignIn|Challenge|AuthControllerLogin)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LoginIdentifierRegex();

    [GeneratedRegex(@"\b(?:Logout|SignOut|EndSession)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutIdentifierRegex();

    [GeneratedRegex(@"\b(?:Me|CurrentUser|Current_User|SessionState|UserInfo|AuthState)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MeIdentifierRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/login[""']|[""']/login[""']|\bChallengeResult\b|\bChallenge\s*\(|\bOpenIdConnectDefaults\.AuthenticationScheme\b|\bAuthController\s*\.\s*Login\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LoginBehaviorRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/logout[""']|[""']/logout[""']|\bSignOutResult\b|\bSignOut\s*\(|\bSignOutAsync\s*\(|\bCookieAuthenticationDefaults\.AuthenticationScheme\b|\bOpenIdConnectDefaults\.AuthenticationScheme\b|\bValidateAntiForgeryToken\b|\bAutoValidateAntiforgeryToken\b|\bAuthController\s*\.\s*Logout\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutBehaviorRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/me[""']|[""']/me[""']|[""']current-user[""']|\bClaimTypes\b|\bClaimsPrincipal\b|\bClaimsIdentity\b|\bIsAuthenticated\b|\bUser\.Identity\b|\bAuthController\s*\.\s*Me\s*\(|\bAssert\.\w+\s*\([^\r\n;]*(?:claim|claims|user|identity|authenticated|unauthenticated)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MeBehaviorRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/login[""']|[""']/login[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LoginRouteRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/logout[""']|[""']/logout[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutRouteRegex();

    [GeneratedRegex(@"[""']/?(?:api/)?auth/me[""']|[""']/me[""']|[""']current-user[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MeRouteRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:Challenge|Redirect|Found|StatusCode)|\bChallengeResult\b|\bOpenIdConnectDefaults\.AuthenticationScheme\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LoginAssertionRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:SignOut|Redirect|Found|NoContent|StatusCode|Cookie)|\bSignOutResult\b|\bCookieAuthenticationDefaults\.AuthenticationScheme\b|\bOpenIdConnectDefaults\.AuthenticationScheme\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LogoutAssertionRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:claim|claims|user|identity|authenticated|unauthenticated|name)|\bClaimTypes\b|\bClaimsPrincipal\b|\bClaimsIdentity\b|\bIsAuthenticated\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MeAssertionRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"\$*""""""[\s\S]*?""""""", RegexOptions.CultureInvariant)]
    private static partial Regex RawStringLiteralRegex();

    [GeneratedRegex(@"(?:\$@|@\$|@)""(?:""""|[^""])*""", RegexOptions.CultureInvariant)]
    private static partial Regex VerbatimStringLiteralRegex();

    [GeneratedRegex(@"\$?""(?:\\.|[^""\\])*""", RegexOptions.CultureInvariant)]
    private static partial Regex RegularStringLiteralRegex();

    private sealed class BehaviorSignals
    {
        public bool HasLogin { get; set; }

        public bool HasLogout { get; set; }

        public bool HasMe { get; set; }

        public string? FirstEvidencePath { get; set; }
    }
}

public sealed record AuthEndpointBehaviorTestResult(
    bool HasLogin,
    bool HasLogout,
    bool HasMe,
    string? EvidencePath)
{
    public bool HasAllBehaviors => HasLogin && HasLogout && HasMe;

    public IReadOnlyList<string> MissingBehaviors
    {
        get
        {
            var missing = new List<string>();
            if (!HasLogin)
            {
                missing.Add("login");
            }

            if (!HasLogout)
            {
                missing.Add("logout");
            }

            if (!HasMe)
            {
                missing.Add("me/current-user");
            }

            return missing;
        }
    }
}
