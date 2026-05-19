using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class MinimalFrontendClaimsExposureRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenNoIdentityEndpointExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [HttpGet("health")]
                public IActionResult Health() => Ok();
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEndpointReturnsUserClaims()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
            }
            """));

        var finding = Assert.Single(new MinimalFrontendClaimsExposureRule().Evaluate(snapshot));

        Assert.Equal("HARDENING-029", finding.RuleId);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEndpointReturnsClaimsPrincipal()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(User);
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEndpointReturnsHttpContextUser()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(HttpContext.User);
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEndpointReturnsAccessToken()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public async Task<IActionResult> Me()
            {
                var token = await HttpContext.GetTokenAsync("access_token");
                return Ok(new { access_token = token });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEndpointReturnsAuthenticationProperties()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public async Task<IActionResult> Me()
            {
                var result = await HttpContext.AuthenticateAsync();
                return Ok(result.Properties);
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenMeEndpointReturnsCuratedDto()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(new CurrentUserResponse
                {
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    Name = User.Identity?.Name,
                    Roles = User.Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value)
                        .ToArray()
                });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenMeEndpointUsesExplicitAllowlistMapping()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(MapFrontendClaims(User));
            }

            private object MapFrontendClaims(ClaimsPrincipal user)
            {
                return new
                {
                    Name = user.FindFirst(ClaimTypes.Name)?.Value,
                    Email = user.FindFirst(ClaimTypes.Email)?.Value
                };
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenAllowlistNamedMapperReturnsAllClaims()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(MapFrontendClaims(User));
            }

            private object MapFrontendClaims(ClaimsPrincipal user)
            {
                return user.Claims.Select(c => new { c.Type, c.Value });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenToCurrentUserResponseReturnsAllClaims()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(ToCurrentUserResponse(User));
            }

            private object ToCurrentUserResponse(ClaimsPrincipal user)
            {
                return new { Claims = user.Claims };
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenCuratedMapperUsesRolesAndFindFirst()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                return Ok(MapFrontendClaims(User));
            }

            private object MapFrontendClaims(ClaimsPrincipal user)
            {
                return new
                {
                    Name = user.FindFirst(ClaimTypes.Name)?.Value,
                    Email = user.FindFirst(ClaimTypes.Email)?.Value,
                    Roles = user.Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value)
                        .ToArray()
                };
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenAccessTokenOnlyAppearsInLogOrErrorMessage()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                logger.LogDebug("access_token was intentionally not returned");
                var error = "refresh_token unavailable";
                return Ok(new { IsAuthenticated = User.Identity?.IsAuthenticated ?? false, Error = error });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenAuthenticationPropertiesAreUsedInternallyOnly()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public async Task<IActionResult> Me()
            {
                var result = await HttpContext.AuthenticateAsync();
                var issued = result.Properties?.IssuedUtc;
                return Ok(new { IsAuthenticated = User.Identity?.IsAuthenticated ?? false, Issued = issued });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCombinedRouteAndHttpGetReturnClaims()
    {
        var snapshot = Snapshot(PackageController(
            """
            [Route("api/auth/me")]
            [HttpGet]
            public IActionResult Get()
            {
                return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenControllerRouteAndMethodRouteReturnClaims()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            [Route("api/auth")]
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Get()
                {
                    return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
                }
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenMinimalApiMeEndpointReturnsClaims()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            """
            app.MapGet("/api/auth/me", (ClaimsPrincipal User) =>
            {
                return Results.Ok(User.Claims.Select(c => new { c.Type, c.Value }));
            });
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenMinimalApiMeEndpointReturnsCuratedResponse()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            "src/OidcStarter.AspNetCore.Bff/Program.cs",
            """
            app.MapGet("/me", (ClaimsPrincipal user) =>
            {
                return Results.Ok(new
                {
                    IsAuthenticated = user.Identity?.IsAuthenticated ?? false,
                    Name = user.FindFirst(ClaimTypes.Name)?.Value
                });
            });
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenRiskyPatternsOnlyAppearInComments()
    {
        var snapshot = Snapshot(PackageController(
            """
            [HttpGet("me")]
            public IActionResult Me()
            {
                // return Ok(User.Claims);
                // access_token
                return Ok(new { IsAuthenticated = User.Identity?.IsAuthenticated ?? false });
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenFakeEndpointOnlyAppearsInRawString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "public class AuthController : ControllerBase { var sample = \"\"\"\r\n[HttpGet(\"me\")]\r\npublic IActionResult Me() { return Ok(User.Claims); }\r\n\"\"\"; }"));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenRiskyPatternOnlyAppearsInTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Me_ReturnsClaims()
                {
                    Assert.Equal(User.Claims, result.Value);
                }
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenPackageIsSafeEvenIfSampleBackendIsRisky()
    {
        var snapshot = Snapshot(
            PackageController(
                """
                [HttpGet("me")]
                public IActionResult Me()
                {
                    return Ok(new CurrentUserResponse
                    {
                        IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                        Name = User.Identity?.Name
                    });
                }
                """),
            new RepositoryFile(
                "src/Backend/AuthController.cs",
                "src/Backend/AuthController.cs",
                """
                public class AuthController : ControllerBase
                {
                    [HttpGet("me")]
                    public IActionResult Me()
                    {
                        return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
                    }
                }
                """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenSampleBackendFallbackIsRiskyAndNoPackageExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/Backend/AuthController.cs",
            "src/Backend/AuthController.cs",
            """
            public class AuthController : ControllerBase
            {
                [HttpGet("me")]
                public IActionResult Me()
                {
                    return Ok(User.Claims.Select(c => new { c.Type, c.Value }));
                }
            }
            """));

        var findings = new MinimalFrontendClaimsExposureRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    private static RepositoryFile PackageController(string action)
    {
        return new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            $$"""
            public class AuthController : ControllerBase
            {
                {{action}}
            }
            """);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
