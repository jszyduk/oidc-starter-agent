using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AspNetMvcUnsafeEndpointDetector
{
    public static UnsafeEndpointAntiforgeryCoverageResult Inspect(RepositorySnapshot snapshot)
    {
        var candidateFiles = StarterMvcCandidateFiles(snapshot).ToList();
        var hasGlobalAntiforgeryCoverage = candidateFiles
            .Select(file => PrepareContent(file.Content))
            .Any(HasGlobalAntiforgeryCoverage);

        var uncoveredEndpoints = candidateFiles
            .SelectMany(file => FindUnsafeEndpoints(file, hasGlobalAntiforgeryCoverage))
            .Where(endpoint => !endpoint.IsCovered)
            .ToList();

        return new UnsafeEndpointAntiforgeryCoverageResult(uncoveredEndpoints);
    }

    private static IEnumerable<RepositoryFile> StarterMvcCandidateFiles(RepositorySnapshot snapshot)
    {
        var productionFiles = snapshot.Files
            .Where(StarterRepositoryLayoutDetector.IsProductionStarterCodeFile)
            .ToList();
        var packageFiles = productionFiles
            .Where(StarterRepositoryLayoutDetector.IsBffPackageFile)
            .ToList();

        if (packageFiles.Count > 0)
        {
            return packageFiles;
        }

        return productionFiles.Where(StarterRepositoryLayoutDetector.IsSampleBackendFile);
    }

    private static IEnumerable<UnsafeMvcEndpoint> FindUnsafeEndpoints(
        RepositoryFile file,
        bool hasGlobalAntiforgeryCoverage)
    {
        var content = PrepareContent(file.Content);

        foreach (var controller in FindControllerContexts(content))
        {
            foreach (Match methodMatch in MethodRegex().Matches(controller.Body))
            {
                var attributeContext = GetAttributeContext(controller.Body, methodMatch.Index);
                var unsafeMethod = GetUnsafeHttpMethod(attributeContext);
                if (unsafeMethod is null)
                {
                    continue;
                }

                var isIgnored = IgnoreAntiforgeryRegex().IsMatch(attributeContext);
                var isCovered = !isIgnored
                    && (AntiforgeryAttributeRegex().IsMatch(attributeContext)
                        || controller.HasControllerLevelAntiforgery
                        || hasGlobalAntiforgeryCoverage);

                yield return new UnsafeMvcEndpoint(
                    file.RelativePath,
                    controller.Name,
                    methodMatch.Groups["name"].Value,
                    unsafeMethod,
                    isCovered,
                    isIgnored);
            }
        }
    }

    private static IEnumerable<ControllerContext> FindControllerContexts(string content)
    {
        foreach (Match controllerMatch in ControllerClassRegex().Matches(content))
        {
            var bodyStart = content.IndexOf('{', controllerMatch.Index);
            if (bodyStart < 0)
            {
                continue;
            }

            var bodyEnd = FindMatchingBrace(content, bodyStart);
            if (bodyEnd <= bodyStart)
            {
                continue;
            }

            yield return new ControllerContext(
                controllerMatch.Groups["name"].Value,
                content.Substring(bodyStart, bodyEnd - bodyStart + 1),
                AntiforgeryAttributeRegex().IsMatch(GetAttributeContext(content, controllerMatch.Index)));
        }
    }

    private static string GetAttributeContext(string content, int declarationIndex)
    {
        var beforeDeclaration = content[..declarationIndex];
        var match = AttributeBlockBeforeDeclarationRegex().Match(beforeDeclaration);
        return match.Success ? match.Value : string.Empty;
    }

    private static string? GetUnsafeHttpMethod(string attributeContext)
    {
        foreach (Match match in HttpMethodAttributeRegex().Matches(attributeContext))
        {
            var method = match.Groups["method"].Value;
            if (IsUnsafeMethod(method))
            {
                return "Http" + method;
            }
        }

        foreach (Match match in AcceptVerbsAttributeRegex().Matches(attributeContext))
        {
            var methods = match.Groups["method"].Captures
                .Select(capture => capture.Value);
            var unsafeMethod = methods.FirstOrDefault(IsUnsafeMethod);
            if (unsafeMethod is not null)
            {
                return "AcceptVerbs(" + unsafeMethod.ToUpperInvariant() + ")";
            }
        }

        return null;
    }

    private static bool IsUnsafeMethod(string method)
    {
        return method.Equals("Post", StringComparison.OrdinalIgnoreCase)
            || method.Equals("Put", StringComparison.OrdinalIgnoreCase)
            || method.Equals("Patch", StringComparison.OrdinalIgnoreCase)
            || method.Equals("Delete", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasGlobalAntiforgeryCoverage(string content)
    {
        return GlobalAntiforgeryFilterRegex().IsMatch(content)
            || GlobalAntiforgeryMiddlewareRegex().IsMatch(content);
    }

    private static int FindMatchingBrace(string content, int openBraceIndex)
    {
        var depth = 0;

        for (var index = openBraceIndex; index < content.Length; index++)
        {
            if (content[index] == '{')
            {
                depth++;
            }
            else if (content[index] == '}')
            {
                depth--;
                if (depth == 0)
                {
                    return index;
                }
            }
        }

        return -1;
    }

    private static string PrepareContent(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        var withoutRawStrings = RawStringLiteralRegex().Replace(withoutLineComments, "STRING_LITERAL");
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(withoutRawStrings, match => ReplacementForStringLiteral(match.Value));
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, match => ReplacementForStringLiteral(match.Value));
    }

    private static string ReplacementForStringLiteral(string value)
    {
        var unquoted = value;
        if (unquoted.StartsWith("$@", StringComparison.Ordinal)
            || unquoted.StartsWith("@$", StringComparison.Ordinal))
        {
            unquoted = unquoted[2..];
        }
        else if (unquoted.StartsWith('@') || unquoted.StartsWith('$'))
        {
            unquoted = unquoted[1..];
        }

        if (unquoted.Length >= 2 && unquoted.StartsWith('"') && unquoted.EndsWith('"'))
        {
            unquoted = unquoted[1..^1];
        }

        unquoted = unquoted.Replace("\\\"", "\"", StringComparison.Ordinal);

        return IsHttpMethodLiteral(unquoted)
            ? "STRING_LITERAL_" + unquoted.ToUpperInvariant()
            : "STRING_LITERAL";
    }

    private static bool IsHttpMethodLiteral(string value)
    {
        return value.Equals("GET", StringComparison.OrdinalIgnoreCase)
            || value.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
            || value.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase)
            || value.Equals("POST", StringComparison.OrdinalIgnoreCase)
            || value.Equals("PUT", StringComparison.OrdinalIgnoreCase)
            || value.Equals("PATCH", StringComparison.OrdinalIgnoreCase)
            || value.Equals("DELETE", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"\[\s*Http(?<method>Get|Post|Put|Patch|Delete|Head|Options)(?:Attribute)?(?:\s*\([^\)]*\))?\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HttpMethodAttributeRegex();

    [GeneratedRegex(@"\[\s*AcceptVerbs(?:Attribute)?\s*\([^\)]*(?:STRING_LITERAL_|[""'])(?<method>GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)(?:[""']|)[^\)]*\)\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AcceptVerbsAttributeRegex();

    [GeneratedRegex(@"(?:\s*\[[^\]]+\]\s*)+$", RegexOptions.CultureInvariant)]
    private static partial Regex AttributeBlockBeforeDeclarationRegex();

    [GeneratedRegex(@"\[\s*(?:AutoValidateAntiforgeryToken|ValidateAntiForgeryToken)(?:Attribute)?(?:\s*\([^\)]*\))?\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AntiforgeryAttributeRegex();

    [GeneratedRegex(@"\[\s*IgnoreAntiforgeryToken(?:Attribute)?(?:\s*\([^\)]*\))?\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IgnoreAntiforgeryRegex();

    [GeneratedRegex(@"\boptions\.Filters\.Add\s*\(\s*(?:new\s+AutoValidateAntiforgeryTokenAttribute\s*\(\s*\)|typeof\s*\(\s*AutoValidateAntiforgeryTokenAttribute\s*\))|\bfilters\.Add\s*\(\s*(?:new\s+AutoValidateAntiforgeryTokenAttribute\s*\(\s*\)|typeof\s*\(\s*AutoValidateAntiforgeryTokenAttribute\s*\))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GlobalAntiforgeryFilterRegex();

    [GeneratedRegex(@"\b(?:app\.)?(?:UseAntiforgery|RequireAntiforgery)\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GlobalAntiforgeryMiddlewareRegex();

    [GeneratedRegex(@"\bpublic\s+(?:async\s+)?[\w<>,\s\[\]\?\.]+\s+(?<name>\w+)\s*\([^)]*\)\s*(?:where\s+[^={]+)?(?:\{|=>)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MethodRegex();

    [GeneratedRegex(@"\b(?:(?:public|internal|sealed|abstract|partial)\s+)*class\s+(?<name>\w*Controller)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ControllerClassRegex();

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
}

internal sealed record ControllerContext(
    string Name,
    string Body,
    bool HasControllerLevelAntiforgery);

public sealed record UnsafeEndpointAntiforgeryCoverageResult(
    IReadOnlyList<UnsafeMvcEndpoint> UncoveredEndpoints)
{
    public bool HasUncoveredEndpoints => UncoveredEndpoints.Count > 0;
}

public sealed record UnsafeMvcEndpoint(
    string FilePath,
    string ControllerName,
    string ActionName,
    string HttpMethod,
    bool IsCovered,
    bool IsIgnored)
{
    public string DisplayName => $"{ControllerName}.{ActionName} [{HttpMethod}]";
}
