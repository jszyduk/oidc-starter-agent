using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static class StarterRepositoryLayoutDetector
{
    public static bool IsBffPackageFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        return path.StartsWith("src/OidcStarter.AspNetCore.Bff/", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSampleBackendFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        return path.StartsWith("src/Backend/", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsBffTestsFile(RepositoryFile file)
    {
        var path = NormalizePath(file.RelativePath);
        return path.StartsWith("src/OidcStarter.AspNetCore.Bff.Tests/", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsProductionStarterCodeFile(RepositoryFile file)
    {
        return file.RelativePath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
            && !IsBffTestsFile(file)
            && !IsLikelyTestFile(file.RelativePath);
    }

    private static bool IsLikelyTestFile(string relativePath)
    {
        var normalizedPath = NormalizePath(relativePath);
        var fileName = Path.GetFileName(normalizedPath);

        return normalizedPath.Contains("/tests/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains("/test/", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.Contains(".Tests", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('\\', '/');
    }
}
