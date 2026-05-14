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
    public void BffAntiforgeryFlowRule_ReturnsNoFinding_WhenCompleteBffAntiforgeryFlowExists()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", """
                public class AntiforgeryController : ControllerBase
                {
                    public IActionResult Token([FromServices] IAntiforgery antiforgery)
                    {
                        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                        Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!);
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", """
                fetch("/api/orders", {
                    method: "POST",
                    headers: { "X-CSRF-TOKEN": token }
                });
                """));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenOnlyBackendSetupExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenOnlyBroadMentionExists()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", "This app should think about antiforgery and CSRF."));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenOnlyHeaderConventionIsDocumented()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", "Send the X-CSRF-TOKEN header with writes."));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenBackendSetupAndTokenIssuingExistWithoutHeaderUsage()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", """
                public class AntiforgeryController : ControllerBase
                {
                    public IActionResult Token([FromServices] IAntiforgery antiforgery)
                    {
                        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                        Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!);
                        return Ok();
                    }
                }
                """));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenHeaderUsageExistsWithoutBackendSetup()
    {
        var snapshot = Snapshot(new RepositoryFile("src/app/api.ts", "src/app/api.ts", """
            fetch("/api/orders", {
                method: "POST",
                headers: { "X-CSRF-TOKEN": token }
            });
            """));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenCSharpSignalsOnlyAppearInComments()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                // builder.Services.AddAntiforgery(options => { });
                // antiforgery.GetAndStoreTokens(HttpContext);
                // Response.Cookies.Append("XSRF-TOKEN", token);
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenBackendSignalsOnlyAppearInTestFiles()
    {
        var snapshot = Snapshot(
            new RepositoryFile("tests/OidcStarter.Agent.Tests/AntiforgeryFlowTests.cs", "tests/OidcStarter.Agent.Tests/AntiforgeryFlowTests.cs", """
                builder.Services.AddAntiforgery(options => { });
                var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!);
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenIAntiforgeryExistsWithoutBackendSetup()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", """
                public class AntiforgeryController : ControllerBase
                {
                    public IActionResult Token([FromServices] IAntiforgery antiforgery)
                    {
                        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                        return Ok(tokens.RequestToken);
                    }
                }
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsNoFinding_WhenUseAntiforgeryCompletesFlow()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "app.UseAntiforgery();"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", """
                public class AntiforgeryController : ControllerBase
                {
                    public IActionResult Token([FromServices] IAntiforgery antiforgery)
                    {
                        var tokens = antiforgery.GetTokens(HttpContext);
                        return Ok(tokens.RequestToken);
                    }
                }
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "new HttpHeaders().set(\"X-CSRF-TOKEN\", token);"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenCookieAppendIsUnrelatedToTokenIssuing()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                builder.Services.AddAntiforgery(options => { });
                Response.Cookies.Append("theme", "dark");
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenFrontendHasBareCsrfVariable()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "const csrf = \"abc\";"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsNoFinding_WhenFrontendUsesHttpHeaders()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "new HttpHeaders().set(\"X-CSRF-TOKEN\", token);"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenMarkdownHasOnlyGenericCsrfProse()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("README.md", "README.md", "CSRF is important for browser applications."));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsNoFinding_WhenMarkdownDocumentsExplicitHeaderName()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("README.md", "README.md", "Send X-CSRF-TOKEN with browser-to-BFF write requests."));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsNoFinding_WhenCustomRequestVerificationHeaderIsUsed()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-Request-Verification-Token\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenBackendSignalsOnlyAppearInSingularTestPath()
    {
        var snapshot = Snapshot(
            new RepositoryFile("test/AuthFlow.cs", "test/AuthFlow.cs", """
                builder.Services.AddAntiforgery(options => { });
                var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                """),
            new RepositoryFile("src/app/api.ts", "src/app/api.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffAntiforgeryFlowRule_ReturnsFinding_WhenHeaderUsageOnlyAppearsInFrontendSpecFile()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAntiforgery(options => { });"),
            new RepositoryFile("src/AntiforgeryController.cs", "src/AntiforgeryController.cs", "var tokens = antiforgery.GetAndStoreTokens(HttpContext);"),
            new RepositoryFile("src/app/app.component.spec.ts", "src/app/app.component.spec.ts", "headers: { \"X-CSRF-TOKEN\": token }"));

        var findings = new BffAntiforgeryFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsNoFinding_WhenAuthenticationPrecedesAuthorization()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.Run();
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenCorrectPipelineAndAuthorizationOnlyPipelineExist()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                var builder = WebApplication.CreateBuilder(args);
                var app = builder.Build();

                app.UseAuthentication();
                app.UseAuthorization();
                """),
            new RepositoryFile("src/AdminPipeline.cs", "src/AdminPipeline.cs", """
                public static class AdminPipeline
                {
                    public static void MapAdmin(WebApplication app)
                    {
                        app.UseAuthorization();
                    }
                }
                """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-014", finding.RuleId);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenAuthorizationPrecedesAuthentication()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            app.UseAuthorization();
            app.UseAuthentication();
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-014", finding.RuleId);
        Assert.Contains("ASPNET-HOST-001", finding.Recommendation);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenAuthorizationExistsWithoutAuthentication()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            app.UseRouting();
            app.UseAuthorization();
            app.MapControllers();
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-014", finding.RuleId);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenAuthenticationOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            var builder = WebApplication.CreateBuilder(args);
            var app = builder.Build();

            // app.UseAuthentication();
            app.UseAuthorization();
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenAuthenticationOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(
            new RepositoryFile("tests/PipelineTests.cs", "tests/PipelineTests.cs", """
                app.UseAuthentication();
                app.UseAuthorization();
                """),
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                var builder = WebApplication.CreateBuilder(args);
                var app = builder.Build();

                app.UseAuthorization();
                """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsNoFinding_WhenNoAspNetCorePipelineExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Widget.cs", "src/Widget.cs", """
            public sealed class Widget
            {
                public string Name { get; init; } = "";
            }
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsNoFinding_WhenMiddlewareCallsOnlyAppearInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            var sample = "app.UseAuthentication(); app.UseAuthorization();";
            """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenStringLiteralWouldOtherwiseMaskInvalidPipeline()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                var builder = WebApplication.CreateBuilder(args);
                var app = builder.Build();

                app.UseAuthorization();
                """),
            new RepositoryFile("src/Samples.cs", "src/Samples.cs", """
                public static class Samples
                {
                    public const string Middleware = "app.UseAuthentication(); app.UseAuthorization();";
                }
                """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AspNetAuthenticationAuthorizationMiddlewareOrderRule_ReturnsFinding_WhenMiddlewareOrderIsSplitAcrossFiles()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/Program.cs", "src/Program.cs", """
                var builder = WebApplication.CreateBuilder(args);
                var app = builder.Build();

                app.UseAuthorization();
                """),
            new RepositoryFile("src/PipelineExtensions.cs", "src/PipelineExtensions.cs", """
                public static class PipelineExtensions
                {
                    public static void AddAuth(this WebApplication app)
                    {
                        app.UseAuthentication();
                    }
                }
                """));

        var findings = new AspNetAuthenticationAuthorizationMiddlewareOrderRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Contains("could not be verified", finding.Description);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenBffFrontendCallsBackendSessionEndpoints()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            this.http.get("/api/auth/me", { withCredentials: true });
            this.http.get("/api/auth/login", { withCredentials: true });
            this.http.post("/api/auth/logout", {}, { withCredentials: true });
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenBffFrontendUsesAuthorizationBearer()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            const token = "abc";
            this.http.get("/api/auth/me", {
                headers: { Authorization: `Bearer ${token}` }
            });
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-015", finding.RuleId);
        Assert.Equal("src/frontend/bff-auth-view.component.ts", finding.FilePath);
        Assert.Contains("BFF-ARCH-002", finding.Recommendation);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenBffFrontendUsesAccessToken()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            const authMode = 'bff';
            const tokenName = 'access_token';
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenTokenHandlingIsSpaSpecific()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/spa-auth-view.component.ts", "src/frontend/spa-auth-view.component.ts", """
            import { OidcSecurityService } from 'angular-auth-oidc-client';
            const tokenName = 'access_token';
            const headers = { Authorization: `Bearer ${token}` };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenSharedBffAuthCodeUsesBearerToken()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/auth.service.ts", "src/frontend/auth.service.ts", """
            const authMode = 'bff';
            const options = {
                setHeaders: { Authorization: `Bearer ${token}` }
            };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenSharedSpaAuthCodeUsesBearerToken()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/auth.service.ts", "src/frontend/auth.service.ts", """
            const authMode = 'spa';
            const headers = { Authorization: `Bearer ${token}` };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenSharedFileHasSpaAndBffMarkersWithBearerToken()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/auth.service.ts", "src/frontend/auth.service.ts", """
            const spaMode = { authMode: 'spa' };
            const bffMode = { authMode: 'bff' };
            this.http.get("/api/auth/me");
            const headers = { Authorization: `Bearer ${token}` };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenBearerTokenIsInSpaBranchOfSharedBffFile()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/auth.service.ts", "src/frontend/auth.service.ts", """
            const modes = ['bff', 'spa'];
            this.http.get("/api/auth/me");

            if (mode === 'spa') {
                headers = { Authorization: `Bearer ${token}` };
            }
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.True(
            findings.Count == 1,
            "Conservative static behavior: shared files with explicit BFF markers and bearer-token handling are reported even when the token handling appears in a SPA branch.");
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenPathContainsSpaButExplicitBffModeExists()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/spa-compat/bff-auth.service.ts", "src/frontend/spa-compat/bff-auth.service.ts", """
            const authMode = 'bff';
            this.http.get("/api/auth/me");
            const headers = { Authorization: `Bearer ${token}` };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenSuspiciousTermsOnlyAppearInComments()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            // Authorization: Bearer abc
            // access_token
            this.http.get("/api/auth/me", { withCredentials: true });
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenOnlyCookieRequestSettingAndUnrelatedAuthorizationExist()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/http.service.ts", "src/frontend/http.service.ts", """
            this.http.get("/api/widgets", { withCredentials: true });
            const label = "Authorization required";
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenTokenTextOnlyAppearsInDisplayString()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            this.http.get("/api/auth/me", { withCredentials: true });
            const message = "access_token error";
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenNoBffFrontendIndicatorsExist()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/widget.component.ts", "src/frontend/widget.component.ts", """
            export class WidgetComponent {
                title = "Widget";
            }
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenBffFrontendCallsTokenEndpoint()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/bff-auth-view.component.ts", "src/frontend/bff-auth-view.component.ts", """
            this.http.get("/api/auth/me", { withCredentials: true });
            this.http.post("/realms/demo/protocol/openid-connect/token", body);
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenEnvironmentConfigContainsBothModes()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/src/environments/environment.development.ts", "src/frontend/src/environments/environment.development.ts", """
            export const environment = {
                authMode: 'bff',
                sampleAuthMode: 'spa',
                authority: 'http://localhost:8080/realms/demo',
                clientId: 'oidc-starter',
                redirectUrl: 'http://localhost:4200/callback',
                postLogoutRedirectUri: 'http://localhost:4200',
                scope: 'openid profile',
                responseType: 'code'
            };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenEnvironmentConfigContainsSpaOidcConfigAndBffMode()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/src/environments/environment.ts", "src/frontend/src/environments/environment.ts", """
            export const environment = {
                authMode: 'bff',
                spaAuth: {
                    authority: 'http://localhost:8080/realms/demo',
                    clientId: 'oidc-starter-spa',
                    redirectUrl: 'http://localhost:4200/callback',
                    scope: 'openid profile',
                    responseType: 'code'
                }
            };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsFinding_WhenEnvironmentConfigContainsAuthorizationBearer()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/src/environments/environment.development.ts", "src/frontend/src/environments/environment.development.ts", """
            export const environment = {
                authMode: 'bff',
                headers: { Authorization: `Bearer ${token}` }
            };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void BffFrontendUsesBackendSessionRule_ReturnsNoFinding_WhenEnvironmentConfigIsSpaSpecific()
    {
        var snapshot = Snapshot(new RepositoryFile("src/frontend/src/environments/environment.development.ts", "src/frontend/src/environments/environment.development.ts", """
            export const environment = {
                authMode: 'spa',
                authority: 'http://localhost:8080/realms/demo',
                clientId: 'oidc-starter-spa',
                redirectUrl: 'http://localhost:4200/callback',
                responseType: 'code'
            };
            """));

        var findings = new BffFrontendUsesBackendSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieHttpOnlyRule_ReturnsNoFinding_WhenHttpOnlyIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            builder.Services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.HttpOnly = true;
            });
            """));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieHttpOnlyRule_ReturnsFinding_WhenHttpOnlyIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAuthentication().AddCookie();"));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-011", finding.RuleId);
        Assert.Contains("BFF-COOKIE-001", finding.Recommendation);
    }

    [Fact]
    public void AuthenticationCookieHttpOnlyRule_ReturnsFinding_WhenHttpOnlyOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "// options.Cookie.HttpOnly = true;"));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieHttpOnlyRule_ReturnsFinding_WhenHttpOnlyOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(new RepositoryFile("tests/AuthCookieTests.cs", "tests/AuthCookieTests.cs", "options.Cookie.HttpOnly = true;"));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsNoFinding_WhenSecurePolicyAlwaysIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            builder.Services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });
            """));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsNoFinding_WhenSecurePolicySameAsRequestIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            builder.Services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });
            """));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsFinding_WhenSecurePolicyIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAuthentication().AddCookie();"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-012", finding.RuleId);
        Assert.Contains("BFF-COOKIE-002", finding.Recommendation);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsFinding_WhenSecurePolicyOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "// options.Cookie.SecurePolicy = CookieSecurePolicy.Always;"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsFinding_WhenSecurePolicyOnlyAppearsInUnrelatedCode()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "var policy = CookieSecurePolicy.Always;"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsFinding_WhenSecurePolicyOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(new RepositoryFile("src/OidcStarter.Agent.Tests/AuthCookie.cs", "src/OidcStarter.Agent.Tests/AuthCookie.cs", "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenSameSiteIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", """
            builder.Services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.SameSite = SameSiteMode.Lax;
            });
            """));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "builder.Services.AddAuthentication().AddCookie();"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-013", finding.RuleId);
        Assert.Contains("BFF-COOKIE-003", finding.Recommendation);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "// options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteOnlyAppearsInUnrelatedCode()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "var sameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthCookieTest.cs", "src/AuthCookieTest.cs", "options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsNoFinding_WhenLogoutCallsSignOutAsync()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            [Route("api/auth")]
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public async Task<IActionResult> Logout()
                {
                    await HttpContext.SignOutAsync();
                    return Ok();
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsNoFinding_WhenLogoutReturnsSignOut()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsNoFinding_WhenLogoutCreatesSignOutResult()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    return new SignOutResult(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsNoFinding_WhenRouteOnlyLogoutActionUsesDifferentMethodName()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult EndSession()
                {
                    return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsFinding_WhenLogoutDoesNotSignOut()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            [Route("api/auth")]
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    return Ok();
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-010", finding.RuleId);
        Assert.Contains("BFF-ARCH-007", finding.Recommendation);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsFinding_WhenSignOutAsyncIsUnrelatedToLogoutAction()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    return Ok();
                }

                public async Task<IActionResult> ClearSomethingElse()
                {
                    await HttpContext.SignOutAsync();
                    return Ok();
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsFinding_WhenOnlyCookieSchemeConstantIsPresent()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    var scheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    return Ok();
                }
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void LogoutClearsLocalSessionRule_ReturnsNoFinding_WhenLogoutEndpointIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me() => Ok();
            }
            """));

        var findings = new LogoutClearsLocalSessionRule().Evaluate(snapshot);

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
    public void ProductionHardeningDocumentationRule_ReturnsNoFinding_WhenReadmeHasSectionAndConcreteTopics()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", """
            ## Production hardening

            Before deploying this BFF starter, require HTTPS, configure SameSite cookies,
            enable CSRF protection, and move secrets out of local development settings.
            """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenReadmeHasOnlyGenericSecurityText()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", "Security is important."));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-016", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenTopicsOnlyAppearInCodeFence()
    {
        var readme = string.Join(Environment.NewLine, [
            "## Production hardening",
            "```csharp",
            "options.Cookie.SameSite = SameSiteMode.Lax;",
            "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;",
            "builder.Services.AddCors();",
            "var secret = configuration[\"ClientSecret\"];",
            "```"
        ]);
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", readme));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenTopicsOnlyAppearInIndentedCodeBlock()
    {
        var readme = string.Join(Environment.NewLine, [
            "## Production hardening",
            "    options.Cookie.SameSite = SameSiteMode.Lax;",
            "    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;",
            "    builder.Services.AddCors();",
            "    var secret = configuration[\"ClientSecret\"];"
        ]);
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", readme));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsNoFinding_WhenDocsFileHasHardeningNotes()
    {
        var snapshot = Snapshot(new RepositoryFile("docs/security.md", "docs/security.md", """
            ## Production readiness

            Before production, require HTTPS, configure explicit CORS origins,
            store secrets in environment-specific secret stores, and enable forwarded headers
            when the app runs behind a reverse proxy.
            """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsNoFinding_WhenSecurityMarkdownHasHardeningNotes()
    {
        var snapshot = Snapshot(new RepositoryFile("SECURITY.md", "SECURITY.md", """
            ## Production caveats

            Use HTTPS for BFF deployments, configure SameSite cookies deliberately,
            and keep secrets outside committed development configuration.
            """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsNoFinding_WhenProductionDocsHaveHardeningNotes()
    {
        var snapshot = Snapshot(new RepositoryFile("docs/production.md", "docs/production.md", """
            ## Before production

            Require HTTPS, configure CORS origins, store secrets outside source control,
            and enable forwarded headers behind a reverse proxy.
            """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenSignalsAreScatteredAcrossFiles()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "## Production hardening"),
            new RepositoryFile("docs/hosting.md", "docs/hosting.md", "HTTPS and CORS are deployment concerns."),
            new RepositoryFile("docs/secrets.md", "docs/secrets.md", "Keep secrets out of source control."));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlySecurityBaselineHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("docs/security-baseline-v1.md", "docs/security-baseline-v1.md", """
                Production security hardening includes HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlyRootChangelogHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("CHANGELOG.md", "CHANGELOG.md", """
                Production security hardening changed HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsNoFinding_WhenReadmeIsMissingAndNoDocsExist()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Program.cs", "src/Program.cs", "Console.WriteLine(\"hello\");"));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlySampleOutputHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("sample-output/audit-report.md", "sample-output/audit-report.md", """
                Production security hardening includes HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlyReportsDirectoryHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("reports/anything.md", "reports/anything.md", """
                Production security hardening includes HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlyRootAuditReportHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("audit-report.md", "audit-report.md", """
                Production security hardening includes HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ProductionHardeningDocumentationRule_ReturnsFinding_WhenOnlyRootGeneratedReportHasHardeningNotes()
    {
        var snapshot = Snapshot(
            new RepositoryFile("README.md", "README.md", "OIDC starter"),
            new RepositoryFile("security-report.md", "security-report.md", """
                Production security hardening includes HTTPS, SameSite, CSRF, CORS, secrets, and forwarded headers.
                """));

        var findings = new ProductionHardeningDocumentationRule().Evaluate(snapshot);

        Assert.Single(findings);
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
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenOnlyKeycloakRoadmapDocExists()
    {
        var snapshot = Snapshot(new RepositoryFile("docs/keycloak-roadmap.md", "docs/keycloak-roadmap.md", """
            Keycloak support is planned for a future milestone.
            """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("No local Keycloak setup detected", finding.Title);
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenReadmeOnlyMentionsKeycloak()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", "Keycloak is supported."));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("No local Keycloak setup detected", finding.Title);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenKeycloakSetupHasDevelopmentOnlyDocumentation()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", """
                Local Keycloak setup is for development only and must not be used in production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenComposeYmlHasKeycloakSetup()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/compose.yml", "infra/compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("docs/keycloak.md", "docs/keycloak.md", """
                The local Keycloak setup is for development only and must not be used in production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenLocalIdpYmlHasKeycloakSetup()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/local-idp.yml", "infra/local-idp.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", """
                The local identity provider is development-only. Replace it for production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenKeycloakSetupHasNoDevelopmentOnlyWarning()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-006", finding.RuleId);
        Assert.Equal("Local Keycloak setup is not clearly marked as development-only", finding.Title);
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenDevelopmentOnlyWarningExistsWithoutKeycloakSetup()
    {
        var snapshot = Snapshot(new RepositoryFile("README.md", "README.md", """
            Local development only. Do not use in production.
            """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("No local Keycloak setup detected", finding.Title);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenDockerComposeCommentMarksSetupDevelopmentOnly()
    {
        var snapshot = Snapshot(new RepositoryFile("docker-compose.yml", "docker-compose.yml", """
            services:
              keycloak:
                # Local development only. Do not use in production.
                image: quay.io/keycloak/keycloak:latest
            """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenReadmeHasOnlyGenericDevelopmentMention()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", "This project supports development."));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenProductionWarningHasNoKeycloakContext()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", "The sample database is development only and must not be used in production."));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenKeycloakMentionAndUnrelatedProductionWarningExist()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", """
                Keycloak is supported.
                The sample database is not for production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("Local Keycloak setup is not clearly marked as development-only", finding.Title);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenSameSentenceHasKeycloakDevelopmentOnlyWarning()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", """
                The local Keycloak setup is for development only and must not be used in production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsNoFinding_WhenLocalIdentityProviderWarningExists()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("README.md", "README.md", """
                The local identity provider is development-only. Replace it for production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void KeycloakSetupExistsRule_ReturnsFinding_WhenOnlyGeneratedReportsHaveDevelopmentOnlyWarning()
    {
        var snapshot = Snapshot(
            new RepositoryFile("infra/keycloak/docker-compose.yml", "infra/keycloak/docker-compose.yml", """
                services:
                  keycloak:
                    image: quay.io/keycloak/keycloak:latest
                """),
            new RepositoryFile("sample-output/audit-report.md", "sample-output/audit-report.md", """
                Local Keycloak setup is for development only and must not be used in production.
                """),
            new RepositoryFile("reports/some-report.md", "reports/some-report.md", """
                Local Keycloak setup is for development only and must not be used in production.
                """));

        var findings = new KeycloakSetupExistsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot("C:/repo", files);
    }
}
