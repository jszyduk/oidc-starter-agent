using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Detection;

public static partial class AspNetMiddlewareDetector
{
    public enum AuthenticationAuthorizationOrderIssue
    {
        None,
        AuthorizationWithoutAuthentication,
        AuthorizationBeforeAuthentication,
        DifferentFilesOrContexts
    }

    public static bool HasUseAuthentication(RepositorySnapshot snapshot)
    {
        return ProductionPipelineFiles(snapshot).Any(file => file.HasAuthentication);
    }

    public static bool HasUseAuthorization(RepositorySnapshot snapshot)
    {
        return ProductionPipelineFiles(snapshot).Any(file => file.HasAuthorization);
    }

    public static bool HasCorrectAuthenticationAuthorizationOrder(RepositorySnapshot snapshot)
    {
        return ProductionPipelineFiles(snapshot).Any(file => file.HasCorrectOrder);
    }

    public static bool HasLikelyAspNetCoreAppPipeline(RepositorySnapshot snapshot)
    {
        return ProductionPipelineFiles(snapshot).Any();
    }

    public static AuthenticationAuthorizationOrderIssue GetAuthenticationAuthorizationOrderIssue(RepositorySnapshot snapshot)
    {
        var pipelineFiles = ProductionPipelineFiles(snapshot).ToList();
        if (pipelineFiles.Count == 0)
        {
            return AuthenticationAuthorizationOrderIssue.None;
        }

        var filesWithAuthentication = pipelineFiles.Where(file => file.HasAuthentication).ToList();
        var filesWithAuthorization = pipelineFiles.Where(file => file.HasAuthorization).ToList();

        if (filesWithAuthorization.Count == 0)
        {
            return AuthenticationAuthorizationOrderIssue.None;
        }

        if (filesWithAuthentication.Count == 0)
        {
            return AuthenticationAuthorizationOrderIssue.AuthorizationWithoutAuthentication;
        }

        if (filesWithAuthorization.Any(file => file.HasAuthentication && !file.HasCorrectOrder))
        {
            return AuthenticationAuthorizationOrderIssue.AuthorizationBeforeAuthentication;
        }

        var authorizationOnlyFiles = filesWithAuthorization
            .Where(file => !file.HasAuthentication)
            .ToList();

        if (authorizationOnlyFiles.Count > 0)
        {
            return filesWithAuthentication.Count > 0
                ? AuthenticationAuthorizationOrderIssue.DifferentFilesOrContexts
                : AuthenticationAuthorizationOrderIssue.AuthorizationWithoutAuthentication;
        }

        var filesWithBoth = pipelineFiles
            .Where(file => file.HasAuthentication && file.HasAuthorization)
            .ToList();

        if (filesWithBoth.Count == 0)
        {
            return AuthenticationAuthorizationOrderIssue.DifferentFilesOrContexts;
        }

        return AuthenticationAuthorizationOrderIssue.None;
    }

    private static IEnumerable<PipelineFile> ProductionPipelineFiles(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
            .Where(file => !IsTestFile(file.RelativePath))
            .Select(file => new PipelineFile(file.RelativePath, RemoveCommentsAndStrings(file.Content)))
            .Where(file => IsLikelyPipelineFile(file.RelativePath, file.Content));
    }

    private static bool IsLikelyPipelineFile(string relativePath, string content)
    {
        var fileName = Path.GetFileName(relativePath.Replace('\\', '/'));

        return fileName.Equals("Program.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.Equals("Startup.cs", StringComparison.OrdinalIgnoreCase)
            || WebApplicationBuilderRegex().IsMatch(content)
            || UseRoutingRegex().IsMatch(content)
            || UseAuthenticationRegex().IsMatch(content)
            || UseAuthorizationRegex().IsMatch(content)
            || MapControllersRegex().IsMatch(content);
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
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static int FirstUseAuthenticationIndex(string content)
    {
        return UseAuthenticationRegex().Match(content) is { Success: true } match
            ? match.Index
            : -1;
    }

    private static int FirstUseAuthorizationIndex(string content)
    {
        return UseAuthorizationRegex().Match(content) is { Success: true } match
            ? match.Index
            : -1;
    }

    private static string RemoveCommentsAndStrings(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        return StringLiteralRegex().Replace(withoutLineComments, "\"\"");
    }

    private sealed record PipelineFile(string RelativePath, string Content)
    {
        public bool HasAuthentication => FirstUseAuthenticationIndex(Content) >= 0;

        public bool HasAuthorization => FirstUseAuthorizationIndex(Content) >= 0;

        public bool HasCorrectOrder
        {
            get
            {
                var authenticationIndex = FirstUseAuthenticationIndex(Content);
                var authorizationIndex = FirstUseAuthorizationIndex(Content);

                return authenticationIndex >= 0
                    && authorizationIndex >= 0
                    && authenticationIndex < authorizationIndex;
            }
        }
    }

    [GeneratedRegex(@"\bWebApplication\.CreateBuilder\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WebApplicationBuilderRegex();

    [GeneratedRegex(@"\b\w+\.UseRouting\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UseRoutingRegex();

    [GeneratedRegex(@"\b\w+\.UseAuthentication\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UseAuthenticationRegex();

    [GeneratedRegex(@"\b\w+\.UseAuthorization\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UseAuthorizationRegex();

    [GeneratedRegex(@"\b(?:\w+\.)?(?:MapControllers|MapControllerRoute)\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MapControllersRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"@?""(?:""""|\\.|[^""\\])*""", RegexOptions.CultureInvariant)]
    private static partial Regex StringLiteralRegex();
}
