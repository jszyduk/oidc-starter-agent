using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class RoleClaimMappingDetector
{
    public static RoleClaimMappingResult Inspect(RepositorySnapshot snapshot)
    {
        var packageSignals = InspectPackageFiles(snapshot.Files);
        var testSignals = InspectTestFiles(snapshot.Files);

        return new RoleClaimMappingResult(
            packageSignals.HasEvidence && testSignals.HasEvidence,
            packageSignals.HasEvidence,
            testSignals.HasEvidence,
            packageSignals.FirstEvidencePath ?? testSignals.FirstEvidencePath);
    }

    private static MappingSignals InspectPackageFiles(IEnumerable<RepositoryFile> files)
    {
        var result = new MappingSignals();

        foreach (var file in files.Where(file =>
            StarterRepositoryLayoutDetector.IsProductionStarterCodeFile(file)
            && StarterRepositoryLayoutDetector.IsBffPackageFile(file)))
        {
            var content = PrepareContent(file.Content);
            var hasEvidence = PackageMappingRegex().IsMatch(content);
            result.HasEvidence |= hasEvidence;

            if (hasEvidence && result.FirstEvidencePath is null)
            {
                result.FirstEvidencePath = file.RelativePath;
            }
        }

        return result;
    }

    private static MappingSignals InspectTestFiles(IEnumerable<RepositoryFile> files)
    {
        var result = new MappingSignals();

        foreach (var file in files.Where(IsRoleClaimMappingTestCandidate))
        {
            var content = PrepareContent(file.Content);
            var hasEvidence = TestMappingRegex().IsMatch(content);

            result.HasEvidence |= hasEvidence;

            if (hasEvidence && result.FirstEvidencePath is null)
            {
                result.FirstEvidencePath = file.RelativePath;
            }
        }

        return result;
    }

    private static bool IsRoleClaimMappingTestCandidate(RepositoryFile file)
    {
        if (!file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = NormalizePath(file.RelativePath);
        var fileName = Path.GetFileName(path);

        return StarterRepositoryLayoutDetector.IsBffTestsFile(file)
            || path.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || path.Contains(".Tests", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static string PrepareContent(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        var withoutRawStrings = RawStringLiteralRegex().Replace(withoutLineComments, "STRING_LITERAL");
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(withoutRawStrings, "STRING_LITERAL");
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, "STRING_LITERAL");
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    [GeneratedRegex(@"\bIClaimsTransformation\b|\b\w*ClaimsTransformation\b|\b\w*ClaimsTransformer\b|\bIClaims?Mapper\b|\bIRoles?Mapper\b|\bIRoleMapping\b|\bIOidcStarter(?:Role|Claims)Mapper\b|\b\w*(?:Role|Claims)Mapper\b|\bMapRoles\s*\(|\bMapClaims\s*\(|\bTokenValidationParameters\s*\.\s*(?:RoleClaimType|NameClaimType)\b|\b(?:RoleClaimType|NameClaimType)\s*=|\bClaimActions\.Map(?:Unique)?JsonKey\s*\(|\boptions\.ClaimActions\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageMappingRegex();

    [GeneratedRegex(@"\bMapRoles\s*\(|\bMapClaims\s*\(|\b(?:Role|Claims?)Mapper\b|\bClaimTypes\.Role\b|\bRoleClaimType\b|\bNameClaimType\b|\bIClaimsTransformation\b|\b\w*ClaimsTransformation\b|\b\w*ClaimsTransformer\b|\bClaimActions\.Map(?:Unique)?JsonKey\s*\(|\bAssert\.\w+\s*\([^\)]*(?:Role|Claim|claims|roles)|\b(?:Should|Expected|Assert)\w*\b[^\r\n;]*(?:mapped|maps|mapping)[^\r\n;]*(?:role|claim|roles|claims)|\b(?:mapped|maps|mapping)[^\r\n;]*(?:role|claim|roles|claims)[^\r\n;]*(?:Should|Expected|Assert)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TestMappingRegex();

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

    private sealed class MappingSignals
    {
        public bool HasEvidence { get; set; }

        public string? FirstEvidencePath { get; set; }
    }
}

public sealed record RoleClaimMappingResult(
    bool HasExplicitAndTestedMapping,
    bool HasPackageMapping,
    bool HasTestEvidence,
    string? EvidencePath);
