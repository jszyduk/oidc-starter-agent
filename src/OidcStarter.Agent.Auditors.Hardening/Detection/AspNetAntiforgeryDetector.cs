using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Detection;

public static partial class AspNetAntiforgeryDetector
{
    public static bool HasBackendAntiforgeryConfiguration(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot).Any(file => BackendSetupRegex().IsMatch(RemoveComments(file.Content)));
    }

    public static bool HasTokenIssuingFlow(RepositorySnapshot snapshot)
    {
        return ProductionCSharpFiles(snapshot).Any(file =>
        {
            var content = RemoveComments(file.Content);
            return TokenApiRegex().IsMatch(content) || TokenCookieAppendRegex().IsMatch(content);
        });
    }

    public static bool HasFrontendTokenUsageOrDocumentedHeaderConvention(RepositorySnapshot snapshot)
    {
        return snapshot.Files.Any(file =>
        {
            if (IsTestFile(file.RelativePath))
            {
                return false;
            }

            if (IsFrontendFile(file.RelativePath))
            {
                var content = RemoveComments(file.Content);
                return ExplicitHeaderNameRegex().IsMatch(content) && FrontendHeaderContextRegex().IsMatch(content);
            }

            if (file.RelativePath.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
            {
                return ExplicitHeaderNameRegex().IsMatch(file.Content);
            }

            return false;
        });
    }

    public static bool HasMeaningfulBffAntiforgeryFlow(RepositorySnapshot snapshot)
    {
        return HasBackendAntiforgeryConfiguration(snapshot)
            && HasTokenIssuingFlow(snapshot)
            && HasFrontendTokenUsageOrDocumentedHeaderConvention(snapshot);
    }

    private static IEnumerable<RepositoryFile> ProductionCSharpFiles(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Where(file => !IsTestFile(file.RelativePath));
    }

    private static bool IsFrontendFile(string relativePath)
    {
        return relativePath.EndsWith(".ts", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTestFile(string relativePath)
    {
        var normalizedPath = relativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalizedPath);

        return normalizedPath.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.StartsWith("tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.StartsWith("test/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains(".Tests", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".spec.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".test.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".spec.js", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".test.js", StringComparison.OrdinalIgnoreCase);
    }

    private static string RemoveComments(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        return LineCommentRegex().Replace(withoutBlockComments, string.Empty);
    }

    [GeneratedRegex(@"\b(?:builder\.Services\.|services\.)?AddAntiforgery\s*\(|\b(?:app\.)?UseAntiforgery\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BackendSetupRegex();

    [GeneratedRegex(@"\b(?:\w+\.)?GetAndStoreTokens\s*\(|\b(?:\w+\.)?GetTokens\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenApiRegex();

    [GeneratedRegex(@"\bResponse\.Cookies\.Append\s*\(\s*[""'](?:RequestVerificationToken|XSRF-TOKEN|CSRF-TOKEN|X-CSRF-TOKEN|X-XSRF-TOKEN|X-Request-Verification-Token)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenCookieAppendRegex();

    [GeneratedRegex(@"\bX-CSRF-TOKEN\b|\bX-XSRF-TOKEN\b|\bRequestVerificationToken\b|\bX-Request-Verification-Token\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitHeaderNameRegex();

    [GeneratedRegex(@"\bheaders\b|\bsetHeaders\b|\bHttpHeaders\b|\bappend\s*\(|\bset\s*\(|\bwithHeaders\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FrontendHeaderContextRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();
}
