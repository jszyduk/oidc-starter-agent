using OidcStarter.Agent.Auditors.Hardening.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class HardeningRuleTests
{
    [Fact]
    public void ReadmeExistsRule_ReturnsFinding_WhenReadmeIsMissing()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "Console.WriteLine(\"hello\");"));

        var findings = new ReadmeExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-008", finding.RuleId);
    }

    [Fact]
    public void NoTokenStorageInFrontendRule_ReturnsFinding_WhenTokenIsStoredInLocalStorage()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/app/auth.ts", "src/app/auth.ts", "localStorage.setItem('access_token', token);"));

        var findings = new NoTokenStorageInFrontendRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("src/app/auth.ts", finding.FilePath);
        Assert.Equal(FindingSeverity.Critical, finding.Severity);
    }

    [Fact]
    public void NoTokenStorageInFrontendRule_ReturnsFinding_WhenTokenIsStoredInSessionStorage()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/app/auth.ts", "src/app/auth.ts", "sessionStorage.setItem('token', response.token);"));

        var findings = new NoTokenStorageInFrontendRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenNoKeycloakRelatedFilesExist()
    {
        var snapshot = Snapshot(
            new RepositoryFile("docker-compose.yml", "docker-compose.yml", "services: {}"),
            new RepositoryFile("README.md", "README.md", "OIDC starter"));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-006", finding.RuleId);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot("C:/repo", files);
    }
}
