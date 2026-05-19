using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class PackageSampleCompatibilityTestDetector
{
    public static PackageSampleCompatibilityTestResult Inspect(RepositorySnapshot snapshot)
    {
        var hasCompatibilityTestEvidence = false;
        var hasSampleProjectReference = false;
        var hasBuildsTogetherEvidence = false;
        string? firstEvidencePath = null;

        foreach (var file in snapshot.Files.Where(IsEligibleFile))
        {
            var path = NormalizePath(file.RelativePath);
            var structuralContent = StripStructuralComments(path, file.Content);

            if (IsEligibleTestFile(file))
            {
                var content = StripCommentsAndRawStrings(file.Content);
                var codeWithoutStrings = StripStringLiterals(content);
                var identifierText = $"{Path.GetFileNameWithoutExtension(path)}\n{codeWithoutStrings}";

                if (HasCompatibilityTestEvidence(path, content, identifierText, codeWithoutStrings))
                {
                    hasCompatibilityTestEvidence = true;
                    firstEvidencePath ??= file.RelativePath;
                }
            }

            if (IsSampleBackendProject(path) && HasLocalPackageProjectReference(structuralContent))
            {
                hasSampleProjectReference = true;
                firstEvidencePath ??= file.RelativePath;
            }

            if (HasBuildsTogetherEvidence(path, structuralContent))
            {
                hasBuildsTogetherEvidence = true;
                firstEvidencePath ??= file.RelativePath;
            }
        }

        return new PackageSampleCompatibilityTestResult(
            hasCompatibilityTestEvidence,
            hasSampleProjectReference,
            hasBuildsTogetherEvidence,
            firstEvidencePath);
    }

    private static bool HasCompatibilityTestEvidence(
        string path,
        string content,
        string identifierText,
        string codeWithoutStrings)
    {
        var hasExplicitCompatibilityTest = ExplicitCompatibilityRegex().IsMatch(identifierText)
            && TestAttributeRegex().IsMatch(content);
        var hasCompatibilityContext = hasExplicitCompatibilityTest
            || CompatibilityContextRegex().IsMatch(identifierText)
            || CompatibilityContextRegex().IsMatch(content);
        var hasPackageSignal = path.Contains("OidcStarter.AspNetCore.Bff.Tests", StringComparison.OrdinalIgnoreCase)
            || PackageSignalRegex().IsMatch(identifierText)
            || PackageSignalRegex().IsMatch(content);
        var hasSampleSignal = SampleSignalRegex().IsMatch(identifierText)
            || SampleSignalRegex().IsMatch(content)
            || SampleIntegrationCodeRegex().IsMatch(codeWithoutStrings);
        var hasIntegrationSignal = IntegrationSignalRegex().IsMatch(identifierText)
            || IntegrationSignalRegex().IsMatch(content)
            || IntegrationCodeRegex().IsMatch(codeWithoutStrings);
        var hasConcreteSignal = ConcreteCompatibilitySignalRegex().IsMatch(identifierText)
            || ConcreteCompatibilitySignalRegex().IsMatch(content)
            || IntegrationCodeRegex().IsMatch(codeWithoutStrings)
            || SampleIntegrationCodeRegex().IsMatch(codeWithoutStrings);

        return hasCompatibilityContext
            && hasConcreteSignal
            && (hasExplicitCompatibilityTest || (hasPackageSignal && hasSampleSignal && hasIntegrationSignal));
    }

    private static bool IsEligibleFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        if (path.Contains("/bin/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/obj/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/node_modules/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/reports/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/sample-output/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("audit-report", StringComparison.OrdinalIgnoreCase)
            || path.Equals("docs/security-baseline-v1.md", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".sln", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/scripts/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("scripts/", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsEligibleTestFile(RepositoryFile file)
    {
        if (!file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var path = NormalizePath(file.RelativePath);
        if (StarterRepositoryLayoutDetector.IsSampleBackendFile(file)
            || StarterRepositoryLayoutDetector.IsBffPackageFile(file))
        {
            return false;
        }

        if (StarterRepositoryLayoutDetector.IsBffTestsFile(file))
        {
            return true;
        }

        return path.StartsWith("tests/", StringComparison.OrdinalIgnoreCase)
            && IsClearlyTestFile(path, file.Content)
            && IsCompatibilityRelatedTestFile(path, file.Content);
    }

    private static bool IsClearlyTestFile(string path, string content)
    {
        var fileName = Path.GetFileName(path);
        return content.Contains("[Fact]", StringComparison.OrdinalIgnoreCase)
            || content.Contains("[Theory]", StringComparison.OrdinalIgnoreCase)
            || content.Contains("[Test]", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Assert.", StringComparison.OrdinalIgnoreCase)
            || path.Contains(".Tests/", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCompatibilityRelatedTestFile(string path, string content)
    {
        return path.Contains("OidcStarter.AspNetCore.Bff", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Bff", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Backend", StringComparison.OrdinalIgnoreCase)
            || path.Contains("Compatibility", StringComparison.OrdinalIgnoreCase)
            || content.Contains("OidcStarter.AspNetCore.Bff", StringComparison.OrdinalIgnoreCase)
            || content.Contains("WebApplicationFactory", StringComparison.OrdinalIgnoreCase)
            || content.Contains("Backend", StringComparison.OrdinalIgnoreCase)
            || content.Contains("PackageSampleCompatibility", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSampleBackendProject(string path)
    {
        return path.Equals("src/Backend/Backend.csproj", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/Backend.csproj", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasLocalPackageProjectReference(string content)
    {
        return content.Contains("ProjectReference", StringComparison.OrdinalIgnoreCase)
            && content.Contains("OidcStarter.AspNetCore.Bff.csproj", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasBuildsTogetherEvidence(string path, string content)
    {
        if (path.EndsWith(".sln", StringComparison.OrdinalIgnoreCase))
        {
            return content.Contains("Backend.csproj", StringComparison.OrdinalIgnoreCase)
                && content.Contains("OidcStarter.AspNetCore.Bff.csproj", StringComparison.OrdinalIgnoreCase);
        }

        if (!IsBuildOrCiFile(path))
        {
            return false;
        }

        var hasDotnetBuildOrTest = DotnetBuildOrTestRegex().IsMatch(content);
        var mentionsSolution = SolutionRegex().IsMatch(content);
        var mentionsBothProjects = content.Contains("Backend.csproj", StringComparison.OrdinalIgnoreCase)
            && content.Contains("OidcStarter.AspNetCore.Bff.csproj", StringComparison.OrdinalIgnoreCase);

        return hasDotnetBuildOrTest && (mentionsSolution || mentionsBothProjects);
    }

    private static bool IsBuildOrCiFile(string path)
    {
        return path.StartsWith(".github/workflows/", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/scripts/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("scripts/", StringComparison.OrdinalIgnoreCase);
    }

    private static string StripCommentsAndRawStrings(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        return RawStringLiteralRegex().Replace(withoutLineComments, "RAW_STRING_LITERAL");
    }

    private static string StripStringLiterals(string content)
    {
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(content, "STRING_LITERAL");
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, "STRING_LITERAL");
    }

    private static string StripStructuralComments(string path, string content)
    {
        if (path.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
        {
            return XmlCommentRegex().Replace(content, string.Empty);
        }

        if (path.EndsWith(".yml", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/scripts/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("scripts/", StringComparison.OrdinalIgnoreCase))
        {
            var withoutHashComments = HashLineCommentRegex().Replace(content, string.Empty);
            return BatchRemCommentRegex().Replace(withoutHashComments, string.Empty);
        }

        return content;
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:PackageSampleCompatibilityTests|PackageSampleCompatibility|Boots_Sample_Backend_With_Local_Bff_Package|SampleBackendCompatibilityTests)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitCompatibilityRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:PackageSampleCompatibilityTests|PackageSampleCompatibility|Boots_Sample_Backend_With_Local_Bff_Package|SampleBackendCompatibilityTests|SampleBackend|Sample_Backend|LocalBffPackage|BffPackage|OidcStarter\.AspNetCore\.Bff)(?![A-Za-z0-9])|[""'][^""']*(?:package/sample compatibility|sample backend|local bff package|reusable package)[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CompatibilityContextRegex();

    [GeneratedRegex(@"\b(?:WebApplicationFactory|TestServer|CreateClient|HostBuilder|WebHostBuilder|UseSolutionRelativeContentRoot|GetAsync|PostAsync|ProjectReference|Backend\.csproj|OidcStarter\.AspNetCore\.Bff\.csproj|dotnet\s+(?:build|test))\b|[""'][^""']*(?:sample backend host|boot sample backend|boots sample backend|starts backend|calls sample host endpoint|local BFF package|/api/auth/(?:me|login|logout))[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ConcreteCompatibilitySignalRegex();

    [GeneratedRegex(@"\[(?:Fact|Theory|Test)\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TestAttributeRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:OidcStarter\.AspNetCore\.Bff|OidcStarter_AspNetCore_Bff|LocalBffPackage|BffPackage)(?![A-Za-z0-9])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageSignalRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:Backend|Backend\.csproj|SampleBackend|Sample_Backend|SampleApp|Sample_App|ExampleConsumer|Program|WebApplicationFactory)(?![A-Za-z0-9])|[""'][^""']*(?:sample backend|sample app|example consumer|backend integration test)[^""']*[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SampleSignalRegex();

    [GeneratedRegex(@"\b(?:WebApplicationFactory|TestServer|CreateClient|GetAsync|PostAsync|HostBuilder|Microsoft\.AspNetCore\.Mvc\.Testing)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IntegrationCodeRegex();

    [GeneratedRegex(@"\bWebApplicationFactory\s*<\s*Program\s*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SampleIntegrationCodeRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9])(?:WebApplicationFactory|IntegrationTest|IntegrationTests|SampleBackendTest|SampleBackendTests|HostBuilder|TestServer|CreateClient|ApplicationFactory|PackageSampleCompatibility|BootsSampleBackend|StartsBackend)(?![A-Za-z0-9])|[""'][^""']*(?:package/sample compatibility|boots sample backend|starts backend|sample backend integration)[^""']*[""']|[""']/?api/auth/(?:me|login|logout)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IntegrationSignalRegex();

    [GeneratedRegex(@"\bdotnet\s+(?:build|test)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DotnetBuildOrTestRegex();

    [GeneratedRegex(@"\b[\w.-]+\.sln\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SolutionRegex();

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

    [GeneratedRegex(@"<!--[\s\S]*?-->", RegexOptions.CultureInvariant)]
    private static partial Regex XmlCommentRegex();

    [GeneratedRegex(@"^\s*#.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex HashLineCommentRegex();

    [GeneratedRegex(@"^\s*REM(?:\s+.*)?$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex BatchRemCommentRegex();
}

public sealed record PackageSampleCompatibilityTestResult(
    bool HasCompatibilityTestEvidence,
    bool HasSampleProjectReference,
    bool HasBuildsTogetherEvidence,
    string? EvidencePath)
{
    public bool HasCompatibilityEvidence => HasCompatibilityTestEvidence
        || (HasSampleProjectReference && HasBuildsTogetherEvidence);
}
