namespace OidcStarter.Agent.Core;

public sealed record RepositoryFile(
    string RelativePath,
    string FullPath,
    string Content);
