using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class UnauthorizedForbiddenBehaviorTestDetector
{
    public static UnauthorizedForbiddenBehaviorTestResult Inspect(RepositorySnapshot snapshot)
    {
        var result = new AuthorizationFailureSignals();

        foreach (var file in snapshot.Files.Where(IsEligibleTestFile))
        {
            var content = StripCommentsAndRawStrings(file.Content);
            var codeWithoutStrings = StripStringLiterals(content);
            var identifierText = $"{Path.GetFileNameWithoutExtension(NormalizePath(file.RelativePath))}\n{codeWithoutStrings}";

            AddEvidence(
                result,
                file.RelativePath,
                HasUnauthorizedEvidence(identifierText, content, codeWithoutStrings),
                HasForbiddenEvidence(identifierText, content, codeWithoutStrings));
        }

        return new UnauthorizedForbiddenBehaviorTestResult(
            result.HasUnauthorized,
            result.HasForbidden,
            result.FirstEvidencePath);
    }

    private static void AddEvidence(
        AuthorizationFailureSignals result,
        string relativePath,
        bool hasUnauthorized,
        bool hasForbidden)
    {
        result.HasUnauthorized |= hasUnauthorized;
        result.HasForbidden |= hasForbidden;

        if ((hasUnauthorized || hasForbidden) && result.FirstEvidencePath is null)
        {
            result.FirstEvidencePath = relativePath;
        }
    }

    private static bool HasUnauthorizedEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = UnauthorizedIdentifierRegex().IsMatch(identifierText);
        var hasAuthContext = UnauthorizedContextRegex().IsMatch(identifierText)
            || UnauthorizedContextStringRegex().IsMatch(content);
        var hasAssertion = UnauthorizedAssertionRegex().IsMatch(codeWithoutStrings);

        return hasIdentifier && hasAuthContext && hasAssertion;
    }

    private static bool HasForbiddenEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = ForbiddenIdentifierRegex().IsMatch(identifierText);
        var hasAuthzContext = ForbiddenContextRegex().IsMatch(identifierText)
            || ForbiddenContextStringRegex().IsMatch(content);
        var hasAssertion = ForbiddenAssertionRegex().IsMatch(codeWithoutStrings);

        return hasIdentifier && hasAuthzContext && hasAssertion;
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

        return IsClearlyTestFile(path, file.Content) && IsPackageRelatedTestFile(path, file.Content);
    }

    private static bool IsClearlyTestFile(string path, string content)
    {
        var fileName = Path.GetFileName(path);
        return path.StartsWith("tests/", StringComparison.OrdinalIgnoreCase)
            && (content.Contains("[Fact]", StringComparison.OrdinalIgnoreCase)
                || content.Contains("[Theory]", StringComparison.OrdinalIgnoreCase)
                || content.Contains("[Test]", StringComparison.OrdinalIgnoreCase)
                || content.Contains("Assert.", StringComparison.OrdinalIgnoreCase)
                || path.Contains(".Tests/", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
                || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsPackageRelatedTestFile(string path, string content)
    {
        return path.Contains("OidcStarter.AspNetCore.Bff", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Bff", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Authorization", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Authentication", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Forbidden", StringComparison.OrdinalIgnoreCase)
            || content.Contains("OidcStarter.AspNetCore.Bff", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Authorize", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Policy", StringComparison.OrdinalIgnoreCase);
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

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:UnauthorizedResult|Status401Unauthorized|HttpStatusCode\.Unauthorized|ReturnsUnauthorized|RequiresAuthentication|AnonymousUser|AnonymousRequest|Unauthenticated|NotAuthenticated|NotLoggedIn|MissingAuthentication|ChallengeAsync|ReturnsChallenge|ShouldChallenge|NoAuthenticationCookie|NoSessionCookie)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnauthorizedIdentifierRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Unauthorized|UnauthorizedResult|Status401Unauthorized|HttpStatusCode\.Unauthorized|RequiresAuthentication|AnonymousUser|AnonymousRequest|Unauthenticated|NotAuthenticated|NotLoggedIn|Authentication|Authenticated|MissingAuthentication|NoAuthenticationCookie|NoSessionCookie|ShouldChallenge)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnauthorizedContextRegex();

    [GeneratedRegex(@"[""'][^""']*(?:unauthenticated request|anonymous request|not logged in|not authenticated|missing authentication|no authentication cookie|no session cookie|requires authentication|should challenge)[^""']*[""']|[""']401[^""']*(?:unauthorized|unauthenticated|authentication|anonymous|not logged in|challenge)[^""']*[""']|[""'][^""']*(?:unauthorized|unauthenticated|authentication|anonymous|not logged in|challenge)[^""']*401[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnauthorizedContextStringRegex();

    [GeneratedRegex(@"\bAssert\.\w+(?:<[^>\r\n;]*(?:UnauthorizedResult|ChallengeResult|Challenge)[^>\r\n;]*>\s*\(|(?:<[^>\r\n;]+>)?\s*\([^\r\n;]*(?:Status401Unauthorized|HttpStatusCode\.Unauthorized|UnauthorizedResult|ChallengeResult|Challenge))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnauthorizedAssertionRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Status403Forbidden|HttpStatusCode\.Forbidden|ReturnsForbidden|ReturnsForbid|AccessDenied|Denied|NoAccess|InsufficientRole|MissingRole|MissingPermission|InsufficientPermission|RequiresRole|RequiresPolicy|ForbiddenForUser|UserWithoutRequiredRole|UserWithoutRole|WrongRole|WrongPolicy|PolicyFailure)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ForbiddenIdentifierRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Forbidden|Status403Forbidden|HttpStatusCode\.Forbidden|Authorization|Authorize|Role|Policy|Permission|AccessDenied|Denied|NoAccess|InsufficientRole|MissingRole|MissingPermission|InsufficientPermission|RequiresRole|RequiresPolicy|ForbiddenForUser|UserWithoutRequiredRole|UserWithoutRole|WrongRole|WrongPolicy|PolicyFailure)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ForbiddenContextRegex();

    [GeneratedRegex(@"[""'][^""']*(?:user lacks role|user lacks claim|wrong role|wrong policy|insufficient permission|missing role|missing permission|access denied|no access|policy failure)[^""']*[""']|[""']403[^""']*(?:forbidden|authorization|role|policy|permission|access denied|no access)[^""']*[""']|[""'][^""']*(?:forbidden|authorization|role|policy|permission|access denied|no access)[^""']*403[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ForbiddenContextStringRegex();

    [GeneratedRegex(@"\bAssert\.\w+(?:<[^>\r\n;]*(?:ForbidResult|Forbid)[^>\r\n;]*>\s*\(|(?:<[^>\r\n;]+>)?\s*\([^\r\n;]*(?:Status403Forbidden|HttpStatusCode\.Forbidden|ForbidResult|Forbid))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ForbiddenAssertionRegex();

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

    private sealed class AuthorizationFailureSignals
    {
        public bool HasUnauthorized { get; set; }

        public bool HasForbidden { get; set; }

        public string? FirstEvidencePath { get; set; }
    }
}

public sealed record UnauthorizedForbiddenBehaviorTestResult(
    bool HasUnauthorized,
    bool HasForbidden,
    string? EvidencePath)
{
    public bool HasAllBehaviors => HasUnauthorized && HasForbidden;

    public IReadOnlyList<string> MissingCategories
    {
        get
        {
            var missing = new List<string>();
            if (!HasUnauthorized)
            {
                missing.Add("unauthorized");
            }

            if (!HasForbidden)
            {
                missing.Add("forbidden");
            }

            return missing;
        }
    }
}
