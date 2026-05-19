using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class OidcFlowDetector
{
    public static OidcFlowResult Inspect(RepositorySnapshot snapshot)
    {
        var packageFiles = snapshot.Files
            .Where(IsEligiblePackageFile)
            .ToList();
        var sampleFiles = snapshot.Files
            .Where(IsEligibleSampleFile)
            .ToList();

        var candidateFiles = packageFiles.Count > 0 ? packageFiles : sampleFiles;
        string? firstCandidatePath = candidateFiles.FirstOrDefault()?.RelativePath;
        string? firstOidcConfigPath = null;
        string? firstCodeFlowPath = null;

        foreach (var file in candidateFiles)
        {
            var content = PrepareContent(file);
            var hasOidcContext = OidcContextRegex().IsMatch(content);
            var hasCodeFlow = HasCodeFlowResponseType(content);
            var hasRiskyResponseType = HasRiskyResponseType(content);

            if (hasOidcContext && firstOidcConfigPath is null)
            {
                firstOidcConfigPath = file.RelativePath;
            }

            if (hasCodeFlow && firstCodeFlowPath is null)
            {
                firstCodeFlowPath = file.RelativePath;
            }

            if (hasRiskyResponseType)
            {
                return new OidcFlowResult(
                    HasExplicitCodeFlow: hasCodeFlow || firstCodeFlowPath is not null,
                    HasRiskyResponseType: true,
                    HasOidcConfiguration: hasOidcContext || firstOidcConfigPath is not null,
                    EvidencePath: file.RelativePath);
            }
        }

        return new OidcFlowResult(
            HasExplicitCodeFlow: firstCodeFlowPath is not null,
            HasRiskyResponseType: false,
            HasOidcConfiguration: firstOidcConfigPath is not null,
            EvidencePath: firstCodeFlowPath ?? firstOidcConfigPath ?? firstCandidatePath);
    }

    private static bool IsEligiblePackageFile(RepositoryFile file)
    {
        return StarterRepositoryLayoutDetector.IsBffPackageFile(file) && IsEligibleEvidenceFile(file);
    }

    private static bool IsEligibleSampleFile(RepositoryFile file)
    {
        return StarterRepositoryLayoutDetector.IsSampleBackendFile(file) && IsEligibleEvidenceFile(file);
    }

    private static bool IsEligibleEvidenceFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        if (path.Contains("/bin/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/node_modules/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/reports/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/sample-output/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("audit-report", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/wwwroot/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/frontend/", StringComparison.OrdinalIgnoreCase)
            || StarterRepositoryLayoutDetector.IsBffTestsFile(file)
            || IsLikelyTestFile(path))
        {
            return false;
        }

        return path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLikelyTestFile(string path)
    {
        var fileName = Path.GetFileName(path);
        return path.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || path.Contains(".Tests", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static string PrepareContent(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        if (path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            var withoutBlockComments = BlockCommentRegex().Replace(file.Content, string.Empty);
            var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
            return RawStringLiteralRegex().Replace(withoutLineComments, "RAW_STRING_LITERAL");
        }

        if (path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
        {
            return HashLineCommentRegex().Replace(file.Content, string.Empty);
        }

        return file.Content;
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    private static bool HasCodeFlowResponseType(string content)
    {
        return OptionCodeResponseTypeRegex().IsMatch(content)
            || OpenIdConnectOptionsCodeInitializerRegex().IsMatch(content)
            || JsonCodeResponseTypeRegex().IsMatch(content);
    }

    private static bool HasRiskyResponseType(string content)
    {
        return OptionRiskyResponseTypeRegex().IsMatch(content)
            || OpenIdConnectOptionsRiskyInitializerRegex().IsMatch(content)
            || JsonRiskyResponseTypeRegex().IsMatch(content)
            || RiskyFlowWordingRegex().IsMatch(content);
    }

    [GeneratedRegex(@"\b(?:AddOpenIdConnect|OpenIdConnectOptions|OpenIdConnectDefaults|Configure\s*<\s*OpenIdConnectOptions\s*>|AuthorizationCodeReceived|OnAuthorizationCodeReceived)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OidcContextRegex();

    [GeneratedRegex(@"\b(?:AddOpenIdConnect|Configure\s*<\s*OpenIdConnectOptions\s*>)[\s\S]{0,1200}?\b\w+\.ResponseType\s*=\s*(?:OpenIdConnectResponseType\.)?Code\b|\b(?:AddOpenIdConnect|Configure\s*<\s*OpenIdConnectOptions\s*>)[\s\S]{0,1200}?\b\w+\.ResponseType\s*=\s*[""']code[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OptionCodeResponseTypeRegex();

    [GeneratedRegex(@"\bnew\s+OpenIdConnectOptions\s*\{[\s\S]{0,1200}?\bResponseType\s*=\s*(?:(?:OpenIdConnectResponseType\.)?Code|[""']code[""'])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpenIdConnectOptionsCodeInitializerRegex();

    [GeneratedRegex(@"[""']response_type[""']\s*:\s*[""']code[""']|\bresponse_type\s*=\s*code\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsonCodeResponseTypeRegex();

    [GeneratedRegex(@"\b(?:AddOpenIdConnect|Configure\s*<\s*OpenIdConnectOptions\s*>)[\s\S]{0,1200}?\b\w+\.ResponseType\s*=\s*(?:[""'](?:id_token|token|id_token\s+token|code\s+id_token|code\s+token)[""']|OpenIdConnectResponseType\.(?:IdToken|IdTokenToken|CodeIdToken|CodeToken)\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OptionRiskyResponseTypeRegex();

    [GeneratedRegex(@"\bnew\s+OpenIdConnectOptions\s*\{[\s\S]{0,1200}?\bResponseType\s*=\s*(?:[""'](?:id_token|token|id_token\s+token|code\s+id_token|code\s+token)[""']|OpenIdConnectResponseType\.(?:IdToken|IdTokenToken|CodeIdToken|CodeToken)\b)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OpenIdConnectOptionsRiskyInitializerRegex();

    [GeneratedRegex(@"[""']response_type[""']\s*:\s*[""'](?:id_token|token|id_token\s+token|code\s+id_token|code\s+token)[""']|\bresponse_type\s*=\s*(?:id_token|token|id_token\s+token|code\s+id_token|code\s+token)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsonRiskyResponseTypeRegex();

    [GeneratedRegex(@"\b(?:implicit|hybrid)\s+(?:flow|response\s+type|grant)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RiskyFlowWordingRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"\$*""""""[\s\S]*?""""""", RegexOptions.CultureInvariant)]
    private static partial Regex RawStringLiteralRegex();

    [GeneratedRegex(@"^\s*#.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex HashLineCommentRegex();
}

public sealed record OidcFlowResult(
    bool HasExplicitCodeFlow,
    bool HasRiskyResponseType,
    bool HasOidcConfiguration,
    string? EvidencePath)
{
    public bool UsesAuthorizationCodeFlow => HasExplicitCodeFlow && !HasRiskyResponseType;
}
