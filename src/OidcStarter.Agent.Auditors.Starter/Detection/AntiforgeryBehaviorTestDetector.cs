using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AntiforgeryBehaviorTestDetector
{
    public static AntiforgeryBehaviorTestResult Inspect(RepositorySnapshot snapshot)
    {
        var result = new AntiforgeryBehaviorSignals();

        foreach (var file in snapshot.Files.Where(IsEligibleTestFile))
        {
            var content = StripCommentsAndRawStrings(file.Content);
            var codeWithoutStrings = StripStringLiterals(content);
            var identifierText = $"{Path.GetFileNameWithoutExtension(NormalizePath(file.RelativePath))}\n{codeWithoutStrings}";

            AddEvidence(
                result,
                file.RelativePath,
                HasTokenIssuingEvidence(identifierText, content, codeWithoutStrings),
                HasRequestValidationEvidence(identifierText, content, codeWithoutStrings),
                HasUnsafeEndpointProtectionEvidence(identifierText, content, codeWithoutStrings));
        }

        return new AntiforgeryBehaviorTestResult(
            result.HasTokenIssuing,
            result.HasRequestValidation,
            result.HasUnsafeEndpointProtection,
            result.FirstEvidencePath);
    }

    private static void AddEvidence(
        AntiforgeryBehaviorSignals result,
        string relativePath,
        bool hasTokenIssuing,
        bool hasRequestValidation,
        bool hasUnsafeEndpointProtection)
    {
        result.HasTokenIssuing |= hasTokenIssuing;
        result.HasRequestValidation |= hasRequestValidation;
        result.HasUnsafeEndpointProtection |= hasUnsafeEndpointProtection;

        if ((hasTokenIssuing || hasRequestValidation || hasUnsafeEndpointProtection) && result.FirstEvidencePath is null)
        {
            result.FirstEvidencePath = relativePath;
        }
    }

    private static bool HasTokenIssuingEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = TokenIssuingIdentifierRegex().IsMatch(identifierText);
        var hasTokenSpecificEvidence = TokenIssuingCodeRegex().IsMatch(codeWithoutStrings)
            || TokenIssuingStringRegex().IsMatch(content);
        var hasAssertion = TokenIssuingAssertionRegex().IsMatch(codeWithoutStrings);

        return hasIdentifier && hasTokenSpecificEvidence && hasAssertion;
    }

    private static bool HasRequestValidationEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = RequestValidationIdentifierRegex().IsMatch(identifierText);
        var hasAntiforgeryContext = RequestValidationContextRegex().IsMatch(identifierText)
            || RequestValidationCodeRegex().IsMatch(codeWithoutStrings)
            || RequestValidationStringRegex().IsMatch(content);
        var hasAssertion = RequestValidationAssertionRegex().IsMatch(codeWithoutStrings);

        return hasIdentifier && hasAntiforgeryContext && hasAssertion;
    }

    private static bool HasUnsafeEndpointProtectionEvidence(string identifierText, string content, string codeWithoutStrings)
    {
        var hasIdentifier = UnsafeEndpointIdentifierRegex().IsMatch(identifierText);
        var hasUnsafeEndpoint = UnsafeEndpointRegex().IsMatch(identifierText)
            || UnsafeEndpointCodeRegex().IsMatch(codeWithoutStrings)
            || UnsafeEndpointStringRegex().IsMatch(content);
        var hasAntiforgeryContext = UnsafeEndpointAntiforgeryContextRegex().IsMatch(identifierText)
            || UnsafeEndpointAntiforgeryCodeRegex().IsMatch(codeWithoutStrings)
            || UnsafeEndpointStringRegex().IsMatch(content);
        var hasAssertion = UnsafeEndpointAssertionRegex().IsMatch(codeWithoutStrings)
            || RequestValidationAssertionRegex().IsMatch(codeWithoutStrings);

        return hasIdentifier && hasUnsafeEndpoint && hasAntiforgeryContext && hasAssertion;
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
            || path.Contains("Antiforgery", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Csrf", StringComparison.OrdinalIgnoreCase)
            || content.Contains("OidcStarter.AspNetCore.Bff", StringComparison.OrdinalIgnoreCase)
            || content.Contains("OidcStarterValidateAntiforgeryToken", StringComparison.OrdinalIgnoreCase);
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

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Csrf|CSRF|Xsrf|XSRF|AntiforgeryToken|AntiforgeryTokenSet|RequestToken|GetAndStoreTokens|GetTokens|IssuesRequestToken|TokenEndpoint)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenIssuingIdentifierRegex();

    [GeneratedRegex(@"\b(?:GetAndStoreTokens|GetTokens|RequestToken|AntiforgeryToken|AntiforgeryTokenSet)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenIssuingCodeRegex();

    [GeneratedRegex(@"[""'][^""']*(?:X-CSRF-TOKEN|X-XSRF-TOKEN|csrf token|xsrf token|request token|antiforgery cookie)[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenIssuingStringRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:RequestToken|AntiforgeryToken|AntiforgeryTokenSet|Token|Header|Cookie)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenIssuingAssertionRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:ValidateRequestAsync|OidcStarterValidateAntiforgeryToken|OidcStarterValidateAntiforgeryTokenFilter|AntiforgeryValidationException|InvalidAntiforgeryToken|MissingAntiforgeryToken|InvalidCsrfToken|MissingCsrfToken|ValidAntiforgeryToken|ValidCsrfToken)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RequestValidationIdentifierRegex();

    [GeneratedRegex(@"\b(?:ValidateRequestAsync|OidcStarterValidateAntiforgeryToken|OidcStarterValidateAntiforgeryTokenFilter|AntiforgeryValidationException|BadRequestResult|StatusCodes\.Status400BadRequest)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RequestValidationCodeRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:ValidateRequestAsync|OidcStarterValidateAntiforgeryToken|OidcStarterValidateAntiforgeryTokenFilter|AntiforgeryValidationException|InvalidAntiforgeryToken|MissingAntiforgeryToken|ValidAntiforgeryToken|InvalidCsrfToken|MissingCsrfToken|ValidCsrfToken)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RequestValidationContextRegex();

    [GeneratedRegex(@"[""'][^""']*(?:missing antiforgery token|invalid antiforgery token|valid antiforgery token|missing csrf token|invalid csrf token|valid csrf token|rejects request because antiforgery|400 on invalid antiforgery)[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RequestValidationStringRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:BadRequest|Status400BadRequest|AntiforgeryValidationException|ValidateRequestAsync|Reject|Allow|StatusCode)|\b(?:BadRequestResult|StatusCodes\.Status400BadRequest|AntiforgeryValidationException)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RequestValidationAssertionRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Logout|HttpPost|POST|Unsafe|UnsafeMethod|RequiresAntiforgery|WithoutCsrfToken|WithCsrfToken|WithoutAntiforgeryToken|WithAntiforgeryToken|ProtectedByAntiforgery)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointIdentifierRegex();

    [GeneratedRegex(@"\b(?:Logout|HttpPost|PostAsync)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointCodeRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Logout|HttpPost|POST|PostAsync|Unsafe|UnsafeMethod)(?![A-Za-z0-9])|[""']/?(?:api/auth/)?logout[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:WithoutCsrfToken|WithCsrfToken|WithoutAntiforgeryToken|WithAntiforgeryToken|RequiresAntiforgery|ProtectedByAntiforgery|ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|OidcStarterValidateAntiforgeryToken)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointAntiforgeryContextRegex();

    [GeneratedRegex(@"\b(?:ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|OidcStarterValidateAntiforgeryToken)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointAntiforgeryCodeRegex();

    [GeneratedRegex(@"[""'][^""']*(?:POST logout with X-CSRF-TOKEN|POST logout without csrf|without csrf|missing antiforgery token|valid antiforgery token|missing csrf token|valid csrf token|protected by antiforgery|X-CSRF-TOKEN|X-XSRF-TOKEN)[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointStringRegex();

    [GeneratedRegex(@"\bAssert\.\w+\s*\([^\r\n;]*(?:BadRequest|Status400BadRequest|NoContent|Redirect|StatusCode|Reject|Allow)|\b(?:BadRequestResult|StatusCodes\.Status400BadRequest|StatusCodes\.Status204NoContent)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeEndpointAssertionRegex();

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

    private sealed class AntiforgeryBehaviorSignals
    {
        public bool HasTokenIssuing { get; set; }

        public bool HasRequestValidation { get; set; }

        public bool HasUnsafeEndpointProtection { get; set; }

        public string? FirstEvidencePath { get; set; }
    }
}

public sealed record AntiforgeryBehaviorTestResult(
    bool HasTokenIssuing,
    bool HasRequestValidation,
    bool HasUnsafeEndpointProtection,
    string? EvidencePath)
{
    public bool HasSufficientCoverage => CoveredCategoryCount >= 2;

    public int CoveredCategoryCount
    {
        get
        {
            var count = 0;
            if (HasTokenIssuing)
            {
                count++;
            }

            if (HasRequestValidation)
            {
                count++;
            }

            if (HasUnsafeEndpointProtection)
            {
                count++;
            }

            return count;
        }
    }

    public IReadOnlyList<string> MissingCategories
    {
        get
        {
            var missing = new List<string>();
            if (!HasTokenIssuing)
            {
                missing.Add("token issuing");
            }

            if (!HasRequestValidation)
            {
                missing.Add("request validation");
            }

            if (!HasUnsafeEndpointProtection)
            {
                missing.Add("unsafe endpoint protection");
            }

            return missing;
        }
    }
}
