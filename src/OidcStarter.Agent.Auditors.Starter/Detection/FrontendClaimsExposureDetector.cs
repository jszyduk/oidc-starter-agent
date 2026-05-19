using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class FrontendClaimsExposureDetector
{
    public static FrontendClaimsExposureResult Inspect(RepositorySnapshot snapshot)
    {
        var packageFiles = snapshot.Files
            .Where(file => IsProductionCodeFile(file) && StarterRepositoryLayoutDetector.IsBffPackageFile(file))
            .ToList();
        var sampleFiles = snapshot.Files
            .Where(file => IsProductionCodeFile(file) && StarterRepositoryLayoutDetector.IsSampleBackendFile(file))
            .ToList();

        var candidateFiles = packageFiles.Count > 0 ? packageFiles : sampleFiles;
        foreach (var file in candidateFiles)
        {
            var content = StripCommentsAndRawStrings(file.Content);
            foreach (Match minimalEndpoint in MinimalApiEndpointRegex().Matches(content))
            {
                if (HasRiskyExposure(minimalEndpoint.Value))
                {
                    return new FrontendClaimsExposureResult(true, true, file.RelativePath);
                }
            }

            foreach (var endpointBlock in FindEndpointBlocks(content))
            {
                if (HasRiskyExposure(endpointBlock))
                {
                    return new FrontendClaimsExposureResult(true, true, file.RelativePath);
                }
            }
        }

        return new FrontendClaimsExposureResult(false, HasAnyIdentityEndpoint(candidateFiles), null);
    }

    private static bool IsProductionCodeFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        return path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/bin/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/node_modules/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/reports/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/sample-output/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("audit-report", StringComparison.OrdinalIgnoreCase)
            && StarterRepositoryLayoutDetector.IsProductionStarterCodeFile(file);
    }

    private static bool HasAnyIdentityEndpoint(IEnumerable<RepositoryFile> files)
    {
        return files
            .Select(file => StripCommentsAndRawStrings(file.Content))
            .Any(content => FindEndpointBlocks(content).Any());
    }

    private static IEnumerable<string> FindEndpointBlocks(string content)
    {
        var classRoute = ClassRouteRegex().Match(content);
        var classRoutePrefix = classRoute.Success ? classRoute.Groups["route"].Value : string.Empty;
        var matches = PublicMethodRegex().Matches(content);
        for (var i = 0; i < matches.Count; i++)
        {
            var match = matches[i];
            var methodName = match.Groups["name"].Value;
            var start = match.Index;
            var nextStart = i + 1 < matches.Count ? matches[i + 1].Index : content.Length;
            var attributeStart = FindAttributeStart(content, start);
            var block = content[attributeStart..nextStart];
            var attributeText = content[attributeStart..start];

            if (EndpointNameRegex().IsMatch(methodName)
                || EndpointRouteRegex().IsMatch(attributeText)
                || CombinedRouteTargetsEndpoint(classRoutePrefix, attributeText)
                || CombinedRouteTargetsEndpoint(classRoutePrefix, block)
                || EndpointRouteRegex().IsMatch(block)
                || ResponseDtoRegex().IsMatch(block))
            {
                yield return block;
            }
        }
    }

    private static int FindAttributeStart(string content, int methodStart)
    {
        var lineStart = content.LastIndexOf('\n', Math.Max(0, methodStart - 1));
        lineStart = lineStart < 0 ? 0 : lineStart + 1;

        var attributeStart = lineStart;
        var cursor = lineStart;
        while (cursor > 0)
        {
            var previousLineEnd = cursor - 1;
            if (previousLineEnd > 0 && content[previousLineEnd - 1] == '\r')
            {
                previousLineEnd--;
            }

            var previousLineStart = content.LastIndexOf('\n', Math.Max(0, previousLineEnd - 1));
            previousLineStart = previousLineStart < 0 ? 0 : previousLineStart + 1;
            var previousLine = content[previousLineStart..previousLineEnd].Trim();

            if (!previousLine.StartsWith("[", StringComparison.Ordinal))
            {
                break;
            }

            attributeStart = previousLineStart;
            cursor = previousLineStart;
        }

        return attributeStart;
    }

    private static bool HasRiskyExposure(string endpointBlock)
    {
        return ReturnsIdentityObjectRegex().IsMatch(endpointBlock)
            || ReturnsAnonymousUserObjectRegex().IsMatch(endpointBlock)
            || HasReturnedTokenOrAuthProperties(endpointBlock)
            || HasRiskyClaimsExposure(endpointBlock);
    }

    private static bool HasRiskyClaimsExposure(string endpointBlock)
    {
        if (ClaimsDictionaryRegex().IsMatch(endpointBlock)
            || ClaimsAssignmentRegex().IsMatch(endpointBlock))
        {
            return true;
        }

        if (BroadClaimsProjectionRegex().IsMatch(endpointBlock)
            && !RoleOnlyClaimsProjectionRegex().IsMatch(endpointBlock))
        {
            return true;
        }

        return ClaimsCollectionRegex().IsMatch(endpointBlock)
            && !CuratedClaimsUsageRegex().IsMatch(endpointBlock);
    }

    private static bool HasReturnedTokenOrAuthProperties(string endpointBlock)
    {
        if (ReturnedTokenOrAuthPropertiesRegex().IsMatch(endpointBlock))
        {
            return true;
        }

        return GetTokenAsyncRegex().IsMatch(endpointBlock)
            && ReturnedTokenVariableRegex().IsMatch(endpointBlock);
    }

    private static bool CombinedRouteTargetsEndpoint(string classRoutePrefix, string attributeText)
    {
        if (string.IsNullOrWhiteSpace(classRoutePrefix))
        {
            return MethodRouteToIdentityEndpointRegex().IsMatch(attributeText);
        }

        if (!HttpGetAttributeRegex().IsMatch(attributeText))
        {
            return false;
        }

        var methodRoute = MethodRouteRegex().Match(attributeText);
        var route = methodRoute.Success ? $"{classRoutePrefix}/{methodRoute.Groups["route"].Value}" : classRoutePrefix;
        return IdentityRouteTextRegex().IsMatch(route);
    }

    private static string StripCommentsAndRawStrings(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        return RawStringLiteralRegex().Replace(withoutLineComments, "RAW_STRING_LITERAL");
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    [GeneratedRegex(@"\bpublic\s+(?:async\s+)?(?:[\w<>,\s\[\]\?\.]+\s+)(?<name>\w+)\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PublicMethodRegex();

    [GeneratedRegex(@"^(?:Me|GetMe|CurrentUser|GetCurrentUser|Session|GetSession)(?:Async)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EndpointNameRegex();

    [GeneratedRegex(@"\[\s*HttpGet(?:Attribute)?\s*\(\s*[""'](?:/?(?:api/auth/)?(?:me|user|current-user|session)|session-state)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EndpointRouteRegex();

    [GeneratedRegex(@"\[\s*Route(?:Attribute)?\s*\(\s*[""'](?<route>[^""']+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClassRouteRegex();

    [GeneratedRegex(@"\[\s*HttpGet(?:Attribute)?(?:\s*\([^\)]*\))?\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HttpGetAttributeRegex();

    [GeneratedRegex(@"\[\s*HttpGet(?:Attribute)?\s*\(\s*[""'](?<route>[^""']+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MethodRouteRegex();

    [GeneratedRegex(@"\[\s*Route(?:Attribute)?\s*\(\s*[""'](?:/?(?:api/auth/)?(?:me|user|current-user|session)|session-state)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MethodRouteToIdentityEndpointRegex();

    [GeneratedRegex(@"(?:^|/)(?:api/auth/)?(?:me|user|current-user|session)$|session-state", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IdentityRouteTextRegex();

    [GeneratedRegex(@"\bapp\.MapGet\s*\(\s*[""'](?:/?(?:api/auth/)?(?:me|user|current-user|session)|session-state)[""'][\s\S]{0,1200}?\)\s*;", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MinimalApiEndpointRegex();

    [GeneratedRegex(@"\b(?:UserInfo|CurrentUser|AuthState|SessionState|MeResponse)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ResponseDtoRegex();

    [GeneratedRegex(@"\b(?:return\s+)?(?:Ok|Json|Results\.Ok)\s*\(\s*(?:User|HttpContext\.User|User\.Identity)\s*\)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex ReturnsIdentityObjectRegex();

    [GeneratedRegex(@"return\s+new\s*\{[^{}]*\bUser\b[^{}]*\}", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex ReturnsAnonymousUserObjectRegex();

    [GeneratedRegex(@"\b(?:Ok|Json|Results\.Ok)\s*\([^\)]*(?:\b\w+\.Properties\b|AuthenticationProperties|TokenResponse|SecurityToken|JwtSecurityToken|(?:access_token|refresh_token|id_token|AccessToken|RefreshToken|IdToken)\s*=|tokens\s*=)[\s\S]{0,300}?\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ReturnedTokenOrAuthPropertiesRegex();

    [GeneratedRegex(@"\bGetTokenAsync\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GetTokenAsyncRegex();

    [GeneratedRegex(@"\b(?:Ok|Json|Results\.Ok)\s*\(\s*(?:token|accessToken|refreshToken|idToken|tokens)\s*\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ReturnedTokenVariableRegex();

    [GeneratedRegex(@"\b(?:User|HttpContext\.User|ClaimsPrincipal|principal|user)\.Claims\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClaimsCollectionRegex();

    [GeneratedRegex(@"\.Claims\s*\.Select\s*\([^\)]*(?:Type|Value)[\s\S]{0,200}(?:Type|Value)|new\s*\{[^{}]*(?:c|claim)\.Type[^{}]*(?:c|claim)\.Value[^{}]*\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BroadClaimsProjectionRegex();

    [GeneratedRegex(@"\.Claims\s*\.Where\s*\([^\)]*ClaimTypes\.Role[\s\S]{0,200}\.Select\s*\([^\)]*\.Value", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RoleOnlyClaimsProjectionRegex();

    [GeneratedRegex(@"\.Claims\s*\.ToDictionary\s*\([^\)]*(?:Type|Value)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClaimsDictionaryRegex();

    [GeneratedRegex(@"\b[Cc]laims\s*=\s*(?:User|HttpContext\.User|principal|user)\.Claims\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ClaimsAssignmentRegex();

    [GeneratedRegex(@"\b(?:new\s+\w*(?:CurrentUser|UserInfo|AuthState|SessionState|MeResponse)\w*\s*\{|IsAuthenticated|DisplayName|Email|Name|Roles|FindFirst\s*\(|IsInRole\s*\(|ClaimTypes\.(?:Role|Name|NameIdentifier|Email))\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CuratedClaimsUsageRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"\$*""""""[\s\S]*?""""""", RegexOptions.CultureInvariant)]
    private static partial Regex RawStringLiteralRegex();
}

public sealed record FrontendClaimsExposureResult(
    bool HasRiskyExposure,
    bool HasIdentityEndpoint,
    string? EvidencePath);
