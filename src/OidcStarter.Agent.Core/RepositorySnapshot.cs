namespace OidcStarter.Agent.Core;

public sealed record RepositorySnapshot(
    string RootPath,
    IReadOnlyList<RepositoryFile> Files);
