using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class ProductionHardeningDocumentationDetector
{
    private static readonly string[] SectionSignals =
    [
        "production",
        "hardening",
        "security",
        "deployment",
        "production readiness",
        "before production",
        "production caveats"
    ];

    private static readonly string[] TopicSignals =
    [
        "https",
        "cookies",
        "httponly",
        "secure",
        "securepolicy",
        "samesite",
        "csrf",
        "antiforgery",
        "cors",
        "secrets",
        "client secret",
        "environment variables",
        "keycloak development-only",
        "reverse proxy",
        "forwarded headers",
        "redirect uri",
        "logout",
        "token storage",
        "bff",
        "spa caveats"
    ];

    public static ProductionHardeningDocumentationResult Inspect(RepositorySnapshot snapshot)
    {
        var documentationFiles = snapshot.Files
            .Where(IsDocumentationFile)
            .ToList();

        if (documentationFiles.Count == 0)
        {
            return new ProductionHardeningDocumentationResult(false, false);
        }

        var hasHardeningNotes = documentationFiles
            .Select(file => StripMarkdownCodeBlocks(file.Content))
            .Any(HasProductionHardeningNotes);

        return new ProductionHardeningDocumentationResult(true, hasHardeningNotes);
    }

    private static bool IsDocumentationFile(RepositoryFile file)
    {
        var path = file.RelativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(path);

        if (!fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IsIgnoredPath(path))
        {
            return false;
        }

        if (IsInternalAnalyzerDocument(path) || IsLikelyGeneratedReport(path) || IsReleaseHistoryDocument(path))
        {
            return false;
        }

        return path.Equals("README.md", StringComparison.OrdinalIgnoreCase)
            || !path.Contains('/', StringComparison.Ordinal)
            || path.StartsWith("docs/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasProductionHardeningNotes(string content)
    {
        var hasSectionSignal = SectionSignals.Any(signal => ContainsSignal(content, signal));
        var topicSignalCount = TopicSignals.Count(signal => ContainsSignal(content, signal));

        return hasSectionSignal && topicSignalCount >= 3;
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

        return fileName.StartsWith("security-baseline", StringComparison.OrdinalIgnoreCase)
            || fileName.StartsWith("baseline", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyGeneratedReport(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);

        return fileName.Equals("audit-report", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("-report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("_report", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsReleaseHistoryDocument(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);

        return fileName.Equals("changelog", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("changes", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("history", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("release-notes", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("releasenotes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsSignal(string content, string signal)
    {
        return Regex.IsMatch(
            content,
            $@"(?<![a-z0-9]){Regex.Escape(signal)}(?![a-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static string StripMarkdownCodeBlocks(string content)
    {
        var withoutBacktickFences = BacktickFenceRegex().Replace(content, string.Empty);
        var withoutTildeFences = TildeFenceRegex().Replace(withoutBacktickFences, string.Empty);
        return IndentedCodeBlockRegex().Replace(withoutTildeFences, string.Empty);
    }

    [GeneratedRegex(@"```.*?```", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BacktickFenceRegex();

    [GeneratedRegex(@"~~~.*?~~~", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex TildeFenceRegex();

    [GeneratedRegex(@"^(?: {4}|\t).*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex IndentedCodeBlockRegex();
}

public sealed record ProductionHardeningDocumentationResult(
    bool HasDocumentationFiles,
    bool HasProductionHardeningNotes);
