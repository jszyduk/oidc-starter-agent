using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class KeycloakSetupDetector
{
    private static readonly string[] StrongDevelopmentOnlySignals =
    [
        "development only",
        "dev only",
        "demo only",
        "sample only",
        "not for production",
        "do not use in production",
        "replace for production",
        "production requires"
    ];

    private static readonly string[] ContextualDevelopmentSignals =
    [
        "local development",
        "local dev",
        "development identity provider",
        "local keycloak",
        "local identity provider",
        "local idp",
        "local oidc provider",
        "local auth server"
    ];

    private static readonly string[] KeycloakContextSignals =
    [
        "keycloak",
        "local identity provider",
        "local idp",
        "development identity provider",
        "identity provider setup",
        "local oidc provider",
        "local auth server"
    ];

    public static bool HasKeycloakSetup(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => !IsIgnoredPath(file.RelativePath))
            .Any(HasKeycloakSetupSignal);
    }

    public static bool HasDevelopmentOnlyLabeling(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(IsDevelopmentOnlyEvidenceFile)
            .Any(HasDevelopmentOnlySignal);
    }

    public static bool HasDevelopmentOnlyKeycloakSetup(RepositorySnapshot snapshot)
    {
        return HasKeycloakSetup(snapshot) && HasDevelopmentOnlyLabeling(snapshot);
    }

    private static bool HasKeycloakSetupSignal(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        var fileName = Path.GetFileName(path);

        if (IsYamlConfigFile(path) && HasKeycloakConfigSignal(file.Content))
        {
            return true;
        }

        if (fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            && IsLikelyRealmConfigPath(path)
            && HasRealmJsonSignal(file.Content))
        {
            return true;
        }

        return IsConcreteKeycloakConfigPath(path)
            && IsConfigLikeFile(path)
            && HasKeycloakConfigSignal(file.Content);
    }

    private static bool IsDevelopmentOnlyEvidenceFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        var fileName = Path.GetFileName(path);

        if (IsIgnoredPath(path) || IsInternalAnalyzerDocument(path) || IsLikelyGeneratedReport(path))
        {
            return false;
        }

        if (fileName.Equals("README.md", StringComparison.OrdinalIgnoreCase)
            || !path.Contains('/', StringComparison.Ordinal) && fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("docs/", StringComparison.OrdinalIgnoreCase) && fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IsYamlConfigFile(path)
            || path.Contains("keycloak", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                && path.Contains("realm", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasDevelopmentOnlySignal(RepositoryFile file)
    {
        var normalizedContent = NormalizeText(file.Content);
        var blocks = DevelopmentOnlyContextBlocks(normalizedContent, IsConfigLikeFile(NormalizePath(file.RelativePath))).ToList();

        if (blocks.Count == 0)
        {
            return false;
        }

        return blocks.Any(block =>
            HasKeycloakDocumentationContext(block)
            && (StrongDevelopmentOnlySignals.Any(signal => ContainsSignal(block, signal))
                || ContextualDevelopmentSignals.Any(signal => ContainsSignal(block, signal))));
    }

    private static bool HasKeycloakDocumentationContext(string content)
    {
        return KeycloakContextSignals.Any(signal => ContainsSignal(content, signal));
    }

    private static IEnumerable<string> DevelopmentOnlyContextBlocks(string content, bool includeLineWindows)
    {
        var sentences = SentenceSplitRegex()
            .Split(content)
            .Where(sentence => !string.IsNullOrWhiteSpace(sentence))
            .ToList();

        foreach (var sentence in sentences)
        {
            yield return sentence;
        }

        if (!includeLineWindows)
        {
            yield break;
        }

        var lines = content.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            if (!HasDevelopmentOnlyPhrase(lines[index]))
            {
                continue;
            }

            var start = Math.Max(0, index - 2);
            var count = Math.Min(lines.Length - start, 5);
            yield return string.Join('\n', lines.Skip(start).Take(count));
        }
    }

    private static bool HasDevelopmentOnlyPhrase(string content)
    {
        return StrongDevelopmentOnlySignals.Any(signal => ContainsSignal(content, signal))
            || ContextualDevelopmentSignals.Any(signal => ContainsSignal(content, signal));
    }

    private static bool HasKeycloakConfigSignal(string content)
    {
        return content.Contains("keycloak", StringComparison.OrdinalIgnoreCase)
            || content.Contains("quay.io/keycloak/keycloak", StringComparison.OrdinalIgnoreCase)
            || content.Contains("KC_BOOTSTRAP_ADMIN_USERNAME", StringComparison.OrdinalIgnoreCase)
            || content.Contains("KC_BOOTSTRAP_ADMIN_PASSWORD", StringComparison.OrdinalIgnoreCase)
            || content.Contains("KEYCLOAK_ADMIN", StringComparison.OrdinalIgnoreCase)
            || content.Contains("KEYCLOAK_ADMIN_PASSWORD", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasRealmJsonSignal(string content)
    {
        return RealmJsonRegex().IsMatch(content)
            && (ClientsJsonRegex().IsMatch(content)
                || ClientIdJsonRegex().IsMatch(content)
                || content.Contains("keycloak", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyRealmConfigPath(string path)
    {
        var fileName = Path.GetFileName(path);

        return path.Contains("realm", StringComparison.OrdinalIgnoreCase)
            || path.Contains("import", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("keycloak", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsConcreteKeycloakConfigPath(string path)
    {
        return path.StartsWith("infra/keycloak/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("infrastructure/keycloak/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("config/keycloak/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("deploy/keycloak/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("deployment/keycloak/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsConfigLikeFile(string path)
    {
        return IsYamlConfigFile(path)
            || path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".env", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".properties", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsIgnoredPath(string path)
    {
        var normalizedPath = NormalizePath(path);
        var segments = normalizedPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        return segments.Any(segment =>
            segment.Equals("sample-output", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("reports", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("bin", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("obj", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("node_modules", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyGeneratedReport(string path)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);

        return fileName.Equals("audit-report", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("-report", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("_report", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInternalAnalyzerDocument(string path)
    {
        var fileName = Path.GetFileName(path);

        return fileName.StartsWith("security-baseline", StringComparison.OrdinalIgnoreCase)
            || fileName.StartsWith("baseline", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsYamlConfigFile(string path)
    {
        var fileName = Path.GetFileName(path);

        if (!fileName.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            && !fileName.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var nameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);

        return nameWithoutExtension.StartsWith("docker-compose", StringComparison.OrdinalIgnoreCase)
            || nameWithoutExtension.Equals("compose", StringComparison.OrdinalIgnoreCase)
            || nameWithoutExtension.Equals("local-idp", StringComparison.OrdinalIgnoreCase)
            || nameWithoutExtension.Equals("keycloak", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsSignal(string content, string signal)
    {
        return Regex.IsMatch(
            content,
            $@"(?<![a-z0-9]){Regex.Escape(signal)}(?![a-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    private static string NormalizeText(string content)
    {
        return content.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Replace('-', ' ');
    }

    [GeneratedRegex(@"""realm""\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RealmJsonRegex();

    [GeneratedRegex(@"""clients""\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClientsJsonRegex();

    [GeneratedRegex(@"""clientId""\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClientIdJsonRegex();

    [GeneratedRegex(@"(?<=[\.\!\?])\s+|\n{2,}", RegexOptions.CultureInvariant)]
    private static partial Regex SentenceSplitRegex();
}
