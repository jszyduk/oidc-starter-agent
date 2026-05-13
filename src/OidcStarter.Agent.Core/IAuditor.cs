namespace OidcStarter.Agent.Core;

public interface IAuditor
{
    string Name { get; }

    AuditResult Run(RepositorySnapshot snapshot);
}
