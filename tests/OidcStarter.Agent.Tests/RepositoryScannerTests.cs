using OidcStarter.Agent.Auditors.Starter;

namespace OidcStarter.Agent.Tests;

public sealed class RepositoryScannerTests
{
    [Fact]
    public void Scan_IgnoresExcludedDirectories()
    {
        using var testRepository = TestRepository.Create();
        testRepository.WriteFile("src/Program.cs", "Console.WriteLine(\"hello\");");
        testRepository.WriteFile(".git/config", "ignored");
        testRepository.WriteFile("bin/Debug/generated.cs", "ignored");
        testRepository.WriteFile("obj/project.assets.json", "ignored");
        testRepository.WriteFile("node_modules/package/index.ts", "ignored");
        testRepository.WriteFile("dist/main.js", "ignored");
        testRepository.WriteFile("coverage/report.md", "ignored");
        testRepository.WriteFile(".vs/settings.json", "ignored");

        var snapshot = new RepositoryScanner().Scan(testRepository.RootPath);

        Assert.Contains(snapshot.Files, file => file.RelativePath == "src/Program.cs");
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains(".git/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains("bin/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains("obj/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains("node_modules/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains("dist/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains("coverage/", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(snapshot.Files, file => file.RelativePath.Contains(".vs/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Scan_IncludesSupportedFiles()
    {
        using var testRepository = TestRepository.Create();
        var includedPaths = new[]
        {
            "src/App.cs",
            "src/App.csproj",
            "appsettings.json",
            "src/main.ts",
            "src/index.html",
            "README.md",
            "pipeline.yml",
            "compose.yaml",
            "Dockerfile",
            "docker-compose.override.yml"
        };

        foreach (var path in includedPaths)
        {
            testRepository.WriteFile(path, "included");
        }

        testRepository.WriteFile("src/app.js", "excluded");

        var snapshot = new RepositoryScanner().Scan(testRepository.RootPath);
        var relativePaths = snapshot.Files.Select(file => file.RelativePath).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var path in includedPaths)
        {
            Assert.Contains(path, relativePaths);
        }

        Assert.DoesNotContain("src/app.js", relativePaths);
    }
}
