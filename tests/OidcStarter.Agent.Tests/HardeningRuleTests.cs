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
