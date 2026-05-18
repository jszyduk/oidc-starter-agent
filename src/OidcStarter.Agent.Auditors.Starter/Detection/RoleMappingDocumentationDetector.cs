using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class RoleMappingDocumentationDetector
{
    private static readonly string[] TopicSignals =
    [
        "role mapping",
        "roles mapping",
        "claim mapping",
        "claims mapping",
        "map roles",
        "map claims",
        "mapped roles",
        "mapped claims",
        "role mapper",
        "claims mapper",
        "IClaimsTransformation",
        "RoleClaimType",
        "ClaimTypes.Role",
        "Keycloak roles",
        "realm roles",
        "client roles"
    ];

    private static readonly string[] ContextSignals =
    [
        "Keycloak",
        "sample",
        "example",
        "oidc-starter",
        "provider-specific claims",
        "OIDC provider",
        "identity provider",
        "realm_access",
        "resource_access"
    ];

    private static readonly string[] GuidanceSignals =
    [
        "configure",
        "configuration",
        "how to",
        "maps",
        "mapped to",
        "extension point",
        "implement",
        "override",
        "adapt",
        "map provider-specific",
        "use the mapper",
        "map to ClaimTypes.Role",
        "map to application roles",
        "provider-specific claims",
        "replace",
        "customize mapper"
    ];

    public static RoleMappingDocumentationResult Inspect(RepositorySnapshot snapshot)
    {
        var documentationFiles = snapshot.Files
            .Where(IsDocumentationFile)
            .ToList();

        foreach (var file in documentationFiles)
        {
            var content = StripMarkdownCodeBlocks(file.Content);
            if (HasRoleMappingDocumentation(content))
            {
                return new RoleMappingDocumentationResult(true, file.RelativePath);
            }
        }

        return new RoleMappingDocumentationResult(false, documentationFiles.FirstOrDefault()?.RelativePath);
    }

    private static bool HasRoleMappingDocumentation(string content)
    {
        return EvidenceBlocks(content).Any(block =>
            TopicSignals.Any(signal => ContainsSignal(block, signal))
            && ContextSignals.Any(signal => ContainsSignal(block, signal))
            && GuidanceSignals.Any(signal => ContainsSignal(block, signal)));
    }

    private static IEnumerable<string> EvidenceBlocks(string content)
    {
        var normalized = content.Replace("\r\n", "\n", StringComparison.Ordinal);
        return ParagraphSeparatorRegex()
            .Split(normalized)
            .Select(block => block.Trim())
            .Where(block => block.Length > 0);
    }

    private static bool IsDocumentationFile(RepositoryFile file)
    {
        var path = file.RelativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(path);

        if (!fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (IsIgnoredPath(path)
            || IsInternalAnalyzerDocument(path)
            || IsLikelyGeneratedReport(path)
            || IsReleaseHistoryDocument(path))
        {
            return false;
        }

        return path.Equals("README.md", StringComparison.OrdinalIgnoreCase)
            || !path.Contains('/', StringComparison.Ordinal)
            || path.StartsWith("docs/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("src/OidcStarter.AspNetCore.Bff/", StringComparison.OrdinalIgnoreCase);
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
        var normalizedPath = path.Replace('\\', '/');
        var fileName = Path.GetFileNameWithoutExtension(normalizedPath);

        return fileName.Equals("changelog", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("changes", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("history", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("release-notes", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("release_notes", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("changelog", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("release-notes", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("release_notes", StringComparison.OrdinalIgnoreCase);
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

    [GeneratedRegex(@"\n\s*\n+", RegexOptions.CultureInvariant)]
    private static partial Regex ParagraphSeparatorRegex();
}

public sealed record RoleMappingDocumentationResult(
    bool HasDocumentation,
    string? EvidencePath);
