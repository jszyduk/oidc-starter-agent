using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter;

public sealed class RepositoryScanner
{
    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs",
        ".csproj",
        ".json",
        ".ts",
        ".html",
        ".md",
        ".yml",
        ".yaml"
    };

    private static readonly HashSet<string> IgnoredDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git",
        "bin",
        "obj",
        "node_modules",
        "dist",
        "coverage",
        ".vs"
    };

    public RepositorySnapshot Scan(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw new ArgumentException("Repository path is required.", nameof(rootPath));
        }

        var fullRootPath = Path.GetFullPath(rootPath);

        if (!Directory.Exists(fullRootPath))
        {
            throw new DirectoryNotFoundException($"Repository path does not exist: {fullRootPath}");
        }

        var files = new List<RepositoryFile>();
        ScanDirectory(fullRootPath, fullRootPath, files);

        return new RepositorySnapshot(fullRootPath, files.OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static void ScanDirectory(string rootPath, string currentDirectory, List<RepositoryFile> files)
    {
        foreach (var directory in Directory.EnumerateDirectories(currentDirectory))
        {
            var directoryName = Path.GetFileName(directory);
            if (IgnoredDirectories.Contains(directoryName))
            {
                continue;
            }

            ScanDirectory(rootPath, directory, files);
        }

        foreach (var filePath in Directory.EnumerateFiles(currentDirectory))
        {
            if (!ShouldInclude(filePath))
            {
                continue;
            }

            var relativePath = Path.GetRelativePath(rootPath, filePath).Replace(Path.DirectorySeparatorChar, '/');
            var content = File.ReadAllText(filePath);
            files.Add(new RepositoryFile(relativePath, filePath, content));
        }
    }

    private static bool ShouldInclude(string filePath)
    {
        var fileName = Path.GetFileName(filePath);

        if (fileName.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (fileName.StartsWith("docker-compose", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return SupportedExtensions.Contains(Path.GetExtension(filePath));
    }
}
