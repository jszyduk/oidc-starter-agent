using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class HardeningRuleTests
{
    private const string TestRepositoryRoot = "/repo";

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
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenNoUnsafeEndpointsExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenPostEndpointHasNoAntiforgeryCoverage()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-021", finding.RuleId);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal("src/OidcStarter.AspNetCore.Bff/AuthController.cs", finding.FilePath);
        Assert.Contains("AuthController.Logout [HttpPost]", finding.Description);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenControllerOnlyAppearsInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Samples.cs",
            "src/OidcStarter.AspNetCore.Bff/Samples.cs",
            "\"\"\"\r\npublic class AuthController : ControllerBase\r\n{\r\n    [HttpPost(\"logout\")]\r\n    public IActionResult Logout() => Ok();\r\n}\r\n\"\"\";"));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenGlobalFilterOnlyAppearsInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            var sample = "options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());";

            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenPostEndpointHasValidateAntiForgeryToken()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [ValidateAntiForgeryToken]
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenPostEndpointHasAutoValidateAntiforgeryToken()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [AutoValidateAntiforgeryToken]
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenAcceptVerbsPostIsUsed()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [AcceptVerbs("POST")]
                public IActionResult Save() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenAcceptVerbsGetIsUsed()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [AcceptVerbs("GET")]
                public IActionResult Read() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenAcceptVerbsPostHasValidateAntiForgeryToken()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [ValidateAntiForgeryToken]
                [AcceptVerbs("POST")]
                public IActionResult Save() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenControllerHasAutoValidateAntiforgeryToken()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            [AutoValidateAntiforgeryToken]
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenControllerLevelAttributeDoesNotCoverAnotherController()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Controllers.cs",
            "src/OidcStarter.AspNetCore.Bff/Controllers.cs",
            """
            [AutoValidateAntiforgeryToken]
            public class ProtectedController : ControllerBase
            {
                [HttpPost("save")]
                public IActionResult Save() => Ok();
            }

            public class UnprotectedController : ControllerBase
            {
                [HttpPost("delete")]
                public IActionResult Delete() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Contains("UnprotectedController.Delete [HttpPost]", finding.Description);
        Assert.DoesNotContain("ProtectedController.Save", finding.Description);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenHelperMethodAfterControllerHasPostAttribute()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Controllers.cs",
            "src/OidcStarter.AspNetCore.Bff/Controllers.cs",
            """
            [AutoValidateAntiforgeryToken]
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }

            public class Helper
            {
                [HttpPost("not-an-action")]
                public IActionResult NotAnAction() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenGlobalMvcFilterExists()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/ServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/ServiceCollectionExtensions.cs",
                """
                services.AddControllers(options =>
                {
                    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
                });
                """),
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public IActionResult Logout() => Ok();
                }
                """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenEndpointIgnoresAntiforgeryToken()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [IgnoreAntiforgeryToken]
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Contains("opt out", finding.Description);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenOnlyCommentHasAntiforgeryAttribute()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();

                // [ValidateAntiForgeryToken]
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenOnlyTestFileHasGlobalFilter()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public IActionResult Logout() => Ok();
                }
                """),
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
                "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
                "options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());"));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_WhenPackageEndpointUncoveredEvenIfSampleHasGlobalFilter()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
                """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public IActionResult Logout() => Ok();
                }
                """),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());"));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_WhenSampleEndpointProtectedAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/AuthController.cs",
            "src/Backend/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [ValidateAntiForgeryToken]
                [HttpPost("logout")]
                public IActionResult Logout() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Theory]
    [InlineData("HttpPut")]
    [InlineData("HttpPatch")]
    [InlineData("HttpDelete")]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsFinding_ForUnsafeMethods(string attributeName)
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/OrdersController.cs",
            "src/OidcStarter.AspNetCore.Bff/OrdersController.cs",
            $$"""
            public class OrdersController : ControllerBase
            {
                [{{attributeName}}("orders/{id}")]
                public IActionResult Save() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void UnsafeHttpMethodsAntiforgeryCoverageRule_ReturnsNoFinding_ForGetEndpoint()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/StatusController.cs",
            "src/OidcStarter.AspNetCore.Bff/StatusController.cs",
            """
            public class StatusController : ControllerBase
            {
                [HttpGet("status")]
                public IActionResult Status() => Ok();
            }
            """));

        var findings = new UnsafeHttpMethodsAntiforgeryCoverageRule().Evaluate(snapshot);

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
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", """
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
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", "// options.Cookie.HttpOnly = true;"));

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
    public void AuthenticationCookieHttpOnlyRule_ReturnsFinding_WhenPackageProjectExistsWithoutHttpOnlyEvenIfSampleConfiguresIt()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "builder.Services.AddAuthentication().AddCookie();"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "options.Cookie.HttpOnly = true;"));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieHttpOnlyRule_ReturnsNoFinding_WhenSampleBackendConfiguresHttpOnlyAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            "options.Cookie.HttpOnly = true;"));

        var findings = new AuthenticationCookieHttpOnlyRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsNoFinding_WhenSecurePolicyAlwaysIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", """
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
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", """
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
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", "// options.Cookie.SecurePolicy = CookieSecurePolicy.Always;"));

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
    public void AuthenticationCookieSecurePolicyRule_ReturnsFinding_WhenPackageProjectExistsWithoutSecurePolicyEvenIfSampleConfiguresIt()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "builder.Services.AddAuthentication().AddCookie();"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSecurePolicyRule_ReturnsNoFinding_WhenSampleBackendConfiguresSecurePolicyAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;"));

        var findings = new AuthenticationCookieSecurePolicyRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenSameSiteIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", """
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
        var snapshot = Snapshot(new RepositoryFile("src/Backend/Program.cs", "src/Backend/Program.cs", "// options.Cookie.SameSite = SameSiteMode.Lax;"));

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
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteOnlyAppearsInSingularTestPath()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/test/SomeTest.cs",
            "src/OidcStarter.AspNetCore.Bff/test/SomeTest.cs",
            "options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenPackageAssignsSameSiteFromSettings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.Cookie.SameSite = bffSettings.CookieSameSite;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenPackageAssignsCorrelationAndNonceSameSiteFromSettings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            options.CorrelationCookie.SameSite = bffSettings.CookieSameSite;
            options.NonceCookie.SameSite = bffSettings.CookieSameSite;
            """));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenCookieSameSitePropertyIsNotAssignedToSameSiteOption()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "var value = bffSettings.CookieSameSite;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteModeUnspecifiedIsAssigned()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "options.Cookie.SameSite = SameSiteMode.Unspecified;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenPlaceholderValueIsAssigned()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "options.Cookie.SameSite = value;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenSameSiteOnlyAppearsInBffPackageTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            "options.Cookie.SameSite = bffSettings.CookieSameSite;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenSampleBackendConfiguresSameSiteAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            "options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenUnrelatedProductionFileConfiguresSameSite()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/SomeOtherProject/Program.cs",
            "src/SomeOtherProject/Program.cs",
            "options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsNoFinding_WhenPackageProjectConfiguresSameSite()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "options.Cookie.SameSite = bffSettings.CookieSameSite;"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "// options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSameSiteRule_ReturnsFinding_WhenPackageProjectExistsWithoutSameSiteEvenIfSampleConfiguresIt()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "builder.Services.AddAuthentication().AddCookie();"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "options.Cookie.SameSite = SameSiteMode.Lax;"));

        var findings = new AuthenticationCookieSameSiteRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsNoFinding_WhenPackageConfiguresCookieNameString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = "__Host-OidcStarter";
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsNoFinding_WhenPackageAssignsCookieNameFromSettings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = bffSettings.CookieName;
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsNoFinding_WhenCookieBuilderNameHasAuthCookieContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie = new CookieBuilder
                {
                    Name = "__Host-OidcStarter"
                };
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenOptionsCookieNameHasNoAuthCookieContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/SomeOptions.cs",
            "src/OidcStarter.AspNetCore.Bff/SomeOptions.cs",
            """
            public void Configure()
            {
                options.Cookie.Name = "__Host-OidcStarter";
            }
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenCookieNameIsEmptyString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = "";
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenCookieNameIsStringEmpty()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = string.Empty;
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenCookieNameIsNullOrDefault()
    {
        var nullSnapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = null;
            });
            """));
        var defaultSnapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = default;
            });
            """));

        Assert.Single(new AuthenticationCookieNameRule().Evaluate(nullSnapshot));
        Assert.Single(new AuthenticationCookieNameRule().Evaluate(defaultSnapshot));
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenAssignmentOnlyAppearsInRawStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "\"\"\"\r\nservices.AddAuthentication().AddCookie(options =>\r\n{\r\n    options.Cookie.Name = \"__Host-OidcStarter\";\r\n});\r\n\"\"\";"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenAntiforgeryCookieNameIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            """
            services.AddAntiforgery(options =>
            {
                options.Cookie.Name = "XSRF-TOKEN";
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenOnlyBareCookieNamePropertyExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "public string CookieName { get; set; }"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-020", finding.RuleId);
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenCookieNameIsOnlyRead()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "var value = bffSettings.CookieName;"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenAssignmentOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "// options.Cookie.Name = \"__Host-OidcStarter\";"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenAssignmentOnlyAppearsInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "var sample = \"options.Cookie.Name = \\\"__Host-OidcStarter\\\";\";"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenOnlyResponseCookieAppendExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Controller.cs",
            "src/OidcStarter.AspNetCore.Bff/Controller.cs",
            "Response.Cookies.Append(\"__Host-OidcStarter\", value);"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenPackageExistsWithoutNameEvenIfSampleConfiguresIt()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "builder.Services.AddAuthentication().AddCookie();"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                """
                services.AddAuthentication().AddCookie(options =>
                {
                    options.Cookie.Name = "__Host-OidcStarter";
                });
                """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsNoFinding_WhenSampleConfiguresNameAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Cookie.Name = "__Host-OidcStarter";
            });
            """));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieNameRule_ReturnsFinding_WhenNameOnlyAppearsInTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            "options.Cookie.Name = \"__Host-OidcStarter\";"));

        var findings = new AuthenticationCookieNameRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsNoFinding_WhenPackageConfiguresExpireTimeSpan()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.ExpireTimeSpan = TimeSpan.FromHours(8);"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsNoFinding_WhenPackageAssignsExpireTimeSpanFromSettings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.ExpireTimeSpan = bffSettings.CookieExpireTimeSpan;"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsNoFinding_WhenPackageConfiguresCookieMaxAge()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.Cookie.MaxAge = bffSettings.CookieMaxAge;"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsFinding_WhenOnlyBareLifetimePropertyExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "public TimeSpan CookieExpireTimeSpan { get; set; }"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-018", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsFinding_WhenAssignmentOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "// options.ExpireTimeSpan = TimeSpan.FromHours(8);"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsFinding_WhenUnrelatedExpireTimeSpanIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "cacheOptions.ExpireTimeSpan = TimeSpan.FromMinutes(5);"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsFinding_WhenUnrelatedMaxAgeIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "cacheOptions.MaxAge = TimeSpan.FromMinutes(5);"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsFinding_WhenAssignmentOnlyAppearsInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "var sample = \"options.ExpireTimeSpan = TimeSpan.FromHours(8);\";"));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeRule_ReturnsNoFinding_WhenGenericInitializerHasAuthCookieContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Events = new CookieAuthenticationEvents();
                ExpireTimeSpan = TimeSpan.FromHours(8);
            });
            """));

        var findings = new AuthenticationCookieLifetimeRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsNoFinding_WhenSlidingExpirationIsTrue()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.SlidingExpiration = true;"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsNoFinding_WhenSlidingExpirationIsFalse()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.SlidingExpiration = false;"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsNoFinding_WhenSlidingExpirationUsesSettings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "options.SlidingExpiration = bffSettings.CookieSlidingExpiration;"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsFinding_WhenOnlyBarePropertyExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "public bool CookieSlidingExpiration { get; set; }"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-019", finding.RuleId);
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsFinding_WhenAssignmentOnlyAppearsInComment()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "// options.SlidingExpiration = true;"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsFinding_WhenUnrelatedSlidingExpirationIsConfigured()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "src/OidcStarter.AspNetCore.Bff/CacheOptions.cs",
            "cacheOptions.SlidingExpiration = true;"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsFinding_WhenAssignmentOnlyAppearsInStringLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "src/OidcStarter.AspNetCore.Bff/Options.cs",
            "var sample = \"options.SlidingExpiration = true;\";"));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void AuthenticationCookieSlidingExpirationRule_ReturnsNoFinding_WhenGenericInitializerHasAuthCookieContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            """
            services.AddAuthentication().AddCookie(options =>
            {
                options.Events = new CookieAuthenticationEvents();
                SlidingExpiration = false;
            });
            """));

        var findings = new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void AuthenticationCookieLifetimeAndSlidingRules_ReturnFindings_WhenPackageExistsWithoutSettingsEvenIfSampleConfiguresThem()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
                "builder.Services.AddAuthentication().AddCookie();"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                """
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = false;
                """));

        Assert.Single(new AuthenticationCookieLifetimeRule().Evaluate(snapshot));
        Assert.Single(new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot));
    }

    [Fact]
    public void AuthenticationCookieLifetimeAndSlidingRules_ReturnNoFindings_WhenSampleConfiguresSettingsAndNoPackageProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            """
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = false;
            """));

        Assert.Empty(new AuthenticationCookieLifetimeRule().Evaluate(snapshot));
        Assert.Empty(new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot));
    }

    [Fact]
    public void AuthenticationCookieLifetimeAndSlidingRules_ReturnFindings_WhenSettingsOnlyAppearInTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SomeTest.cs",
            """
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = false;
            """));

        Assert.Single(new AuthenticationCookieLifetimeRule().Evaluate(snapshot));
        Assert.Single(new AuthenticationCookieSlidingExpirationRule().Evaluate(snapshot));
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
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenLogoutEndpointIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me() => Ok();
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenLogoutEndpointOnlyAppearsInComments()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                // [HttpPost("logout")]
                // public IActionResult Logout() => Ok();
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenLogoutEndpointOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(new RepositoryFile("tests/AuthControllerTests.cs", "tests/AuthControllerTests.cs", """
            public class AuthControllerTests
            {
                [HttpPost("logout")]
                public async Task<IActionResult> Logout()
                {
                    await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    return Ok();
                }
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenLogoutIsLocalOnlyAndUndocumented()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
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

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        var finding = Assert.Single(findings);
        Assert.Equal("HARDENING-017", finding.RuleId);
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Contains("BFF-ARCH-008", finding.Recommendation);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenLogoutSignsOutOidcScheme()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public async Task<IActionResult> Logout()
                {
                    await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    return Ok();
                }
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenLogoutReturnsOidcSignOutResult()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                [HttpPost("logout")]
                public IActionResult Logout()
                {
                    return SignOut(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectDefaults.AuthenticationScheme);
                }
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenOnlySignedOutCallbackPathIsConfigured()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public IActionResult Logout()
                    {
                        return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
                    }
                }
                """),
            new RepositoryFile("src/Oidc.cs", "src/Oidc.cs", """
                builder.Services.AddAuthentication().AddOpenIdConnect(options =>
                {
                    options.SignedOutCallbackPath = "/signout-callback-oidc";
                });
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenCallbackPathAndOidcSignOutAreConfigured()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("src/Oidc.cs", "src/Oidc.cs", """
                builder.Services.AddAuthentication().AddOpenIdConnect(options =>
                {
                    options.SignedOutCallbackPath = "/signout-callback-oidc";
                });
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenRedirectToIdentityProviderForSignOutIsConfigured()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync();
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("src/Oidc.cs", "src/Oidc.cs", """
                builder.Services.AddAuthentication().AddOpenIdConnect(options =>
                {
                    options.Events.OnRedirectToIdentityProviderForSignOut = context => Task.CompletedTask;
                });
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsNoFinding_WhenDocumentationExplainsLocalVersusProviderLogout()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync();
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("README.md", "README.md", """
                The BFF logout clears the local application cookie. Production applications should decide whether to also sign out from the upstream identity provider / OIDC provider session and configure post-logout redirect behavior as needed.
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenDocumentationIsGeneric()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync();
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("README.md", "README.md", "Logout is supported."));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenOidcSchemeMentionIsOutsideLogoutContext()
    {
        var snapshot = Snapshot(new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
            public class AuthController : ControllerBase
            {
                private readonly string scheme = OpenIdConnectDefaults.AuthenticationScheme;

                [HttpPost("logout")]
                public async Task<IActionResult> Logout()
                {
                    await HttpContext.SignOutAsync();
                    return Ok();
                }
            }
            """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenOidcSignOutOnlyAppearsInTestFile()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync();
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("tests/AuthControllerTests.cs", "tests/AuthControllerTests.cs", """
                public class AuthControllerTests
                {
                    public async Task Logout()
                    {
                        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
                    }
                }
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void OidcIdentityProviderLogoutAwarenessRule_ReturnsFinding_WhenOnlySecurityBaselineDocumentsIdpLogout()
    {
        var snapshot = Snapshot(
            new RepositoryFile("src/AuthController.cs", "src/AuthController.cs", """
                public class AuthController : ControllerBase
                {
                    [HttpPost("logout")]
                    public async Task<IActionResult> Logout()
                    {
                        await HttpContext.SignOutAsync();
                        return Ok();
                    }
                }
                """),
            new RepositoryFile("docs/security-baseline-v1.md", "docs/security-baseline-v1.md", """
                Logout should account for identity-provider sign-out and local cookie behavior.
                """));

        var findings = new OidcIdentityProviderLogoutAwarenessRule().Evaluate(snapshot);

        Assert.Single(findings);
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
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
