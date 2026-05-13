namespace OidcStarter.Agent.Tests;

internal sealed class TestRepository : IDisposable
{
    private TestRepository(string rootPath)
    {
        RootPath = rootPath;
    }

    public string RootPath { get; }

    public static TestRepository Create()
    {
        var rootPath = Path.Combine(Path.GetTempPath(), "oidc-starter-agent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootPath);
        return new TestRepository(rootPath);
    }

    public void WriteFile(string relativePath, string content)
    {
        var normalizedPath = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var fullPath = Path.Combine(RootPath, normalizedPath);
        var directory = Path.GetDirectoryName(fullPath);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(fullPath, content);
    }

    public void Dispose()
    {
        if (Directory.Exists(RootPath))
        {
            Directory.Delete(RootPath, recursive: true);
        }
    }
}
