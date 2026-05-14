using OidcStarter.Agent.Auditors.Hardening.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class HardeningRuleTests
{
    [Fact]
    public void MeEndpointExistsRule_ReturnsNoFinding_WhenHttpGetMeAttributeExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me() => Ok();
            }
            """));

        var findings = new MeEndpointExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LoginEndpointExistsRule_ReturnsNoFinding_WhenHttpPostLoginAttributeExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("login")]
                public IActionResult Login() => Ok();
            }
            """));

        var findings = new LoginEndpointExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LogoutEndpointExistsRule_ReturnsNoFinding_WhenHttpPostLogoutAttributeExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new LogoutEndpointExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void EndpointRules_ReturnNoFindings_WhenControllerUsesRoutePrefixAndActionAttributes()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            [Route("api/auth")]
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me() => Ok();

                [HttpPost("login")]
                public IActionResult Login() => Ok();

                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        Assert.Empty(new MeEndpointExistsRule().Evaluate(snapshot));
        Assert.Empty(new LoginEndpointExistsRule().Evaluate(snapshot));
        Assert.Empty(new LogoutEndpointExistsRule().Evaluate(snapshot));
    }

    [Fact]
    public void EndpointRules_ReturnFindings_WhenNoMvcAuthEndpointsExist()
    {
        var snapshot = Snapshot(new RepositoryFile("src/WeatherController.cs", "src/WeatherController.cs", """
            public class WeatherController : ControllerBase
            {
                [HttpGet("forecast")]
                public IActionResult Forecast() => Ok();
            }
            """));

        Assert.Single(new MeEndpointExistsRule().Evaluate(snapshot));
        Assert.Single(new LoginEndpointExistsRule().Evaluate(snapshot));
        Assert.Single(new LogoutEndpointExistsRule().Evaluate(snapshot));
    }

    [Fact]
    public void BffAuthEndpointsShouldUseControllersRule_ReturnsFinding_WhenMinimalApiAuthEndpointsExist()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            app.MapGet("/api/auth/me", () => Results.Ok());
            app.MapPost("/api/auth/login", () => Results.Ok());
            app.MapPost("/api/auth/logout", () => Results.Ok());
            """));

        var findings = new BffAuthEndpointsShouldUseControllersRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-009", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Equal("src/Program.cs", finding.FilePath);
    }

    [Fact]
    public void EndpointRules_ReturnFindings_WhenAuthEndpointsUseMinimalApi()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            app.MapGet("/api/auth/me", () => Results.Ok());
            app.MapPost("/api/auth/login", () => Results.Ok());
            app.MapPost("/api/auth/logout", () => Results.Ok());
            """));

        Assert.Single(new MeEndpointExistsRule().Evaluate(snapshot));
        Assert.Single(new LoginEndpointExistsRule().Evaluate(snapshot));
        Assert.Single(new LogoutEndpointExistsRule().Evaluate(snapshot));
    }

    [Fact]
    public void BffAuthEndpointsShouldUseControllersRule_ReturnsNoFinding_WhenMinimalApiRoutesAreNotAuthEndpoints()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            app.MapGet("/health", () => Results.Ok());
            app.MapGet("/version", () => Results.Ok());
            """));

        var findings = new BffAuthEndpointsShouldUseControllersRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

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
