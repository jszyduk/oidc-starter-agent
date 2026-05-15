using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class BffFrontendSessionDetector
{
    public static IReadOnlyList<RepositoryFile> GetSuspiciousBffTokenHandlingFiles(RepositorySnapshot snapshot)
    {
        var frontendFiles = FrontendFiles(snapshot).ToList();

        if (!frontendFiles.Any(HasBffFrontendSignal))
        {
            return [];
        }

        return frontendFiles
            .Where(file => HasBffFrontendSignal(file))
            .Where(file => HasExplicitBffSignal(file) || !IsClearlySpaSpecific(file))
            .Where(file => HasBrowserTokenHandlingSignal(file))
            .ToList();
    }

    public static bool HasBffFrontendSessionSignal(RepositorySnapshot snapshot)
    {
        return FrontendFiles(snapshot).Any(HasBffFrontendSignal);
    }

    private static IEnumerable<RepositoryFile> FrontendFiles(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => IsFrontendFile(file.RelativePath))
            .Where(file => !IsLikelyTestFile(file.RelativePath));
    }

    private static bool IsFrontendFile(string relativePath)
    {
        return relativePath.EndsWith(".ts", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || relativePath.EndsWith(".html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyTestFile(string relativePath)
    {
        var normalizedPath = relativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalizedPath);

        return normalizedPath.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.StartsWith("tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.StartsWith("test/", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".spec.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".test.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".spec.js", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".test.js", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasBffFrontendSignal(RepositoryFile file)
    {
        return HasExplicitBffSignal(file) || HasGeneralBffSignal(file);
    }

    private static bool HasExplicitBffSignal(RepositoryFile file)
    {
        var normalizedPath = file.RelativePath.Replace('\\', '/');
        var content = RemoveComments(file.Content);

        return normalizedPath.Contains("bff-auth", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("bff-auth-view", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("/bff/", StringComparison.OrdinalIgnoreCase)
            || BffModeRegex().IsMatch(content)
            || BffEndpointRegex().IsMatch(content);
    }

    private static bool HasGeneralBffSignal(RepositoryFile file)
    {
        var normalizedPath = file.RelativePath.Replace('\\', '/');
        var content = RemoveComments(file.Content);

        return normalizedPath.Contains("bff-auth", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("bff-auth-view", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("/bff/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains(".bff.", StringComparison.OrdinalIgnoreCase)
            || BffModeRegex().IsMatch(content)
            || BffEndpointRegex().IsMatch(content)
            || CookieRequestSettingRegex().IsMatch(content);
    }

    private static bool IsClearlySpaSpecific(RepositoryFile file)
    {
        var normalizedPath = file.RelativePath.Replace('\\', '/');
        var content = RemoveComments(file.Content);

        return normalizedPath.Contains("/spa/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("spa-auth", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("spa-auth-view", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains(".spa.", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("oidc-client", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("angular-auth-oidc", StringComparison.OrdinalIgnoreCase)
            || SpaModeRegex().IsMatch(content);
    }

    private static bool HasBrowserTokenHandlingSignal(RepositoryFile file)
    {
        var content = RemoveComments(file.Content);

        if (IsLikelyEnvironmentOrConfigFile(file.RelativePath))
        {
            return HasRuntimeTokenHandlingSignal(content);
        }

        return HasRuntimeTokenHandlingSignal(content)
            || AuthorizationHeaderRegex().IsMatch(content)
            || RealTokenNameUsageRegex().IsMatch(content)
            || BrowserOidcLibraryRegex().IsMatch(content)
            || DirectFrontendOidcConfigRegex().IsMatch(content);
    }

    private static bool HasRuntimeTokenHandlingSignal(string content)
    {
        return AuthorizationBearerRegex().IsMatch(content)
            || TokenEndpointRegex().IsMatch(content)
            || RuntimeTokenUsageRegex().IsMatch(content);
    }

    private static bool IsLikelyEnvironmentOrConfigFile(string relativePath)
    {
        var normalizedPath = relativePath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalizedPath);

        return normalizedPath.Contains("/environments/", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("environment.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.StartsWith("environment.", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("config.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("auth.config.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("app.config.ts", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".config.ts", StringComparison.OrdinalIgnoreCase);
    }

    private static string RemoveComments(string content)
    {
        var withoutHtmlComments = HtmlCommentRegex().Replace(content, string.Empty);
        var withoutBlockComments = BlockCommentRegex().Replace(withoutHtmlComments, string.Empty);
        return LineCommentRegex().Replace(withoutBlockComments, string.Empty);
    }

    [GeneratedRegex(@"\b(?:authMode|mode)\s*[:=]\s*[""']bff[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BffModeRegex();

    [GeneratedRegex(@"\b(?:authMode|mode)\s*[:=]\s*[""']spa[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SpaModeRegex();

    [GeneratedRegex(@"(?:/)?api/auth/(?:me|login|logout)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BffEndpointRegex();

    [GeneratedRegex(@"\bwithCredentials\s*:\s*true\b|\bcredentials\s*:\s*[""']include[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CookieRequestSettingRegex();

    [GeneratedRegex(@"Authorization\s*:\s*`?\s*Bearer\b|Authorization\s*:\s*[""']Bearer\s*[""']\s*\+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationBearerRegex();

    [GeneratedRegex(@"\bheaders\.Authorization\s*=|\bsetHeaders\s*:\s*\{[^}]*\bAuthorization\s*:|\bnew\s+HttpHeaders\s*\(\s*\{[^}]*\bAuthorization\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline)]
    private static partial Regex AuthorizationHeaderRegex();

    [GeneratedRegex(@"(?<![""'])\b(?:access_token|refresh_token|id_token)\b(?![""'])|[""'](?:access_token|refresh_token|id_token)[""']\s*(?:\]|\)|,|;|:|\+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RealTokenNameUsageRegex();

    [GeneratedRegex(@"\b(?:access_token|refresh_token)\b\s*(?:=|=>|\+\+|--)|(?:=|return)\s*\w*\.(?:access_token|refresh_token)\b|\b(?:getItem|setItem|removeItem)\s*\(\s*[""'](?:access_token|refresh_token)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RuntimeTokenUsageRegex();

    [GeneratedRegex(@"protocol/openid-connect/token|oauth/token|/token\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TokenEndpointRegex();

    [GeneratedRegex(@"angular-auth-oidc-client|oidc-client-ts", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BrowserOidcLibraryRegex();

    [GeneratedRegex(@"\bauthority\s*:|\bclientId\s*:|\bredirectUrl\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DirectFrontendOidcConfigRegex();

    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex HtmlCommentRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();
}
