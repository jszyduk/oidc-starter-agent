using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class AntiforgeryBehaviorTestsRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenTokenIssuingAndValidationEvidenceExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_IssuesRequestToken()
                {
                    var tokens = antiforgery.GetAndStoreTokens(httpContext);
                    Assert.Equal(tokens.RequestToken, response.Headers["X-CSRF-TOKEN"]);
                    Assert.IsType<NoContentResult>(result);
                }

                [Fact]
                public void InvalidAntiforgeryToken_ReturnsBadRequest()
                {
                    var exception = new AntiforgeryValidationException("invalid");
                    Assert.IsType<BadRequestResult>(filter.Handle(exception));
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenTokenIssuingAndValidationExistWithoutUnsafeEndpointEvidence()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_IssuesRequestToken()
                {
                    var tokens = antiforgery.GetAndStoreTokens(httpContext);
                    Assert.NotNull(tokens.RequestToken);
                    Assert.Equal("X-CSRF-TOKEN", headerName);
                }

                [Fact]
                public async Task MissingAntiforgeryToken_ReturnsBadRequest()
                {
                    await Assert.ThrowsAsync<AntiforgeryValidationException>(
                        () => antiforgery.ValidateRequestAsync(httpContext));
                    Assert.IsType<BadRequestResult>(result);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenValidationAndUnsafeEndpointEvidenceExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryFilterTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryFilterTests.cs",
            """
            public class AntiforgeryFilterTests
            {
                [Fact]
                public async Task Filter_Rejects_Invalid_Token()
                {
                    var filter = new OidcStarterValidateAntiforgeryTokenFilter(antiforgery);
                    await antiforgery.ValidateRequestAsync(httpContext);
                    Assert.Equal(StatusCodes.Status400BadRequest, result.StatusCode);
                }

                [Fact]
                public void Logout_WithoutCsrfToken_ReturnsBadRequest()
                {
                    var attribute = new OidcStarterValidateAntiforgeryToken();
                    Assert.IsType<BadRequestResult>(attribute.Validate(HttpPost("logout")));
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenRequestValidationAndLogoutFilterFactoryEvidenceUsePackageAttribute()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/Controllers/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/Controllers/AuthControllerTests.cs",
            """
            public sealed class AuthControllerTests
            {
                [Fact]
                public async Task Logout_request_filter_returns_bad_request_when_antiforgery_validation_fails()
                {
                    var antiforgery = new FakeAntiforgery(throwsOnValidate: true);
                    var method = typeof(AuthController).GetMethod(nameof(AuthController.Logout));
                    var context = CreateAuthorizationFilterContext(httpContext);

                    Assert.NotNull(method);
                    var attribute = Assert.Single(
                        method.GetCustomAttributes(inherit: false),
                        static attribute => attribute is OidcStarterValidateAntiforgeryTokenAttribute);
                    var filterFactory = Assert.IsAssignableFrom<IFilterFactory>(attribute);
                    var filter = Assert.IsAssignableFrom<IAsyncAuthorizationFilter>(
                        filterFactory.CreateInstance(httpContext.RequestServices));

                    await filter.OnAuthorizationAsync(context);

                    Assert.True(antiforgery.ValidateRequestCalled);
                    Assert.IsType<BadRequestResult>(context.Result);
                }

                [Fact]
                public async Task Package_antiforgery_filter_returns_bad_request_when_validation_fails()
                {
                    var filter = new OidcStarterValidateAntiforgeryTokenFilter(
                        new FakeAntiforgery(throwsOnValidate: true));
                    var context = CreateAuthorizationFilterContext();

                    await filter.OnAuthorizationAsync(context);

                    Assert.IsType<BadRequestResult>(context.Result);
                }

                private sealed class FakeAntiforgery(bool throwsOnValidate = false) : IAntiforgery
                {
                    public bool ValidateRequestCalled { get; private set; }

                    public Task ValidateRequestAsync(HttpContext httpContext)
                    {
                        ValidateRequestCalled = true;
                        return Task.CompletedTask;
                    }
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenUrlStringAppearsBeforeAntiforgeryEvidence()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/Controllers/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/Controllers/AuthControllerTests.cs",
            """
            public sealed class AuthControllerTests
            {
                [Fact]
                public void Login_challenges_openid_connect_with_frontend_redirect()
                {
                    Assert.Equal("http://localhost:4200", result.Properties?.RedirectUri);
                }

                [Fact]
                public void Logout_rejects_missing_trusted_origin()
                {
                    controller.HttpContext.Request.Headers.Origin = "http://localhost:4200";
                    Assert.IsType<ForbidResult>(result);
                }

                [Fact]
                public async Task Logout_request_filter_returns_bad_request_when_antiforgery_validation_fails()
                {
                    var antiforgery = new FakeAntiforgery(throwsOnValidate: true);
                    var method = typeof(AuthController).GetMethod(nameof(AuthController.Logout));
                    var context = CreateAuthorizationFilterContext(httpContext);

                    Assert.NotNull(method);
                    var attribute = Assert.Single(
                        method.GetCustomAttributes(inherit: false),
                        static attribute => attribute is OidcStarterValidateAntiforgeryTokenAttribute);
                    var filterFactory = Assert.IsAssignableFrom<IFilterFactory>(attribute);
                    var filter = Assert.IsAssignableFrom<IAsyncAuthorizationFilter>(
                        filterFactory.CreateInstance(httpContext.RequestServices));

                    await filter.OnAuthorizationAsync(context);

                    Assert.True(antiforgery.ValidateRequestCalled);
                    Assert.IsType<BadRequestResult>(context.Result);
                }

                [Fact]
                public async Task Package_antiforgery_filter_returns_bad_request_when_validation_fails()
                {
                    var filter = new OidcStarterValidateAntiforgeryTokenFilter(
                        new FakeAntiforgery(throwsOnValidate: true));
                    var context = CreateAuthorizationFilterContext();

                    await filter.OnAuthorizationAsync(context);

                    Assert.IsType<BadRequestResult>(context.Result);
                }

                private sealed class FakeAntiforgery(bool throwsOnValidate = false) : IAntiforgery
                {
                    public bool ValidateRequestCalled { get; private set; }

                    public Task ValidateRequestAsync(HttpContext httpContext)
                    {
                        ValidateRequestCalled = true;
                        return Task.CompletedTask;
                    }
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenTokenIssuingAndUnsafeEndpointEvidenceExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_IssuesRequestToken()
                {
                    var tokens = antiforgery.GetTokens(httpContext);
                    Assert.NotNull(tokens.RequestToken);
                    Assert.Equal("X-XSRF-TOKEN", headerName);
                }

                [Fact]
                public async Task Logout_WithCsrfToken_AllowsRequest()
                {
                    request.Headers.Add("X-CSRF-TOKEN", tokens.RequestToken);
                    var response = await client.PostAsync("/api/auth/logout", null);
                    Assert.Equal(StatusCodes.Status204NoContent, response.StatusCode);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyTokenIssuingEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_IssuesRequestToken()
                {
                    var tokens = antiforgery.GetAndStoreTokens(httpContext);
                    Assert.Equal(tokens.RequestToken, response.Headers["X-CSRF-TOKEN"]);
                    Assert.IsType<NoContentResult>(result);
                }
            }
            """));

        var finding = Assert.Single(new AntiforgeryBehaviorTestsRule().Evaluate(snapshot));

        Assert.Equal("HARDENING-026", finding.RuleId);
    }

    [Fact]
    public void ReturnsFinding_WhenCsrfEndpointOnlyReturnsNoContent()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_ReturnsNoContent()
                {
                    Assert.IsType<NoContentResult>(result);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCsrfRouteOnlyAssertsNoContentStatus()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public async Task CsrfEndpoint_ReturnsNoContent()
                {
                    var response = await client.GetAsync("/api/auth/csrf");
                    Assert.Equal(StatusCodes.Status204NoContent, response.StatusCode);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyStrongTokenIssuingEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void CsrfEndpoint_IssuesRequestToken()
                {
                    var tokens = antiforgery.GetAndStoreTokens(httpContext);
                    Assert.NotNull(tokens.RequestToken);
                    Assert.Equal("X-CSRF-TOKEN", headerName);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyWeakBadRequestEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void InvalidToken_ReturnsBadRequest()
                {
                    Assert.IsType<BadRequestResult>(result);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyStrongRequestValidationEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public async Task MissingAntiforgeryToken_ReturnsBadRequest()
                {
                    await Assert.ThrowsAsync<AntiforgeryValidationException>(
                        () => antiforgery.ValidateRequestAsync(httpContext));
                    Assert.IsType<BadRequestResult>(result);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenLogoutOnlyAssertsNoContentStatus()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            """
            public class LogoutAntiforgeryTests
            {
                [Fact]
                public void Logout_ReturnsNoContent()
                {
                    Assert.Equal(StatusCodes.Status204NoContent, result.StatusCode);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyStrongUnsafeEndpointEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            """
            public class LogoutAntiforgeryTests
            {
                [Fact]
                public async Task Logout_WithoutCsrfToken_ReturnsBadRequest()
                {
                    var response = await client.PostAsync("/api/auth/logout", null);
                    Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyGenericAntiforgeryMentionExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                [Fact]
                public void Names_Are_Not_Behavior_Evidence()
                {
                    var antiforgery = "antiforgery";
                    Assert.NotNull(antiforgery);
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyTestProjectExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SmokeTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SmokeTests.cs",
            """
            public class SmokeTests
            {
                [Fact]
                public void Builds()
                {
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyProductionCodeHasAntiforgeryImplementation()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Antiforgery/CsrfController.cs",
            "src/OidcStarter.AspNetCore.Bff/Antiforgery/CsrfController.cs",
            """
            public class CsrfController
            {
                public IActionResult Get()
                {
                    var tokens = antiforgery.GetAndStoreTokens(HttpContext);
                    Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken;
                    return NoContent();
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyCommentsMentionAntiforgeryBehavior()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            """
            public class AntiforgeryTests
            {
                // ValidateRequestAsync
                // AntiforgeryValidationException
                // X-CSRF-TOKEN
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenFakeAntiforgeryTestsOnlyAppearInRawString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryTests.cs",
            "var sample = \"\"\"\r\n[Fact]\r\npublic void CsrfEndpoint_IssuesRequestToken() { Assert.Equal(tokens.RequestToken, response.Headers[\"X-CSRF-TOKEN\"]); }\r\n\r\n[Fact]\r\npublic void InvalidAntiforgeryToken_ReturnsBadRequest() { Assert.ThrowsAsync<AntiforgeryValidationException>(() => antiforgery.ValidateRequestAsync(httpContext)); Assert.IsType<BadRequestResult>(result); }\r\n\r\n[Fact]\r\npublic void Logout_WithoutCsrfToken_ReturnsBadRequest() { Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode); }\r\n\"\"\";"));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyDocsMentionAntiforgeryTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "README.md",
            "README.md",
            "Antiforgery token issuing and request validation tests exist."));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyUnsafeEndpointProtectionEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/LogoutAntiforgeryTests.cs",
            """
            public class LogoutAntiforgeryTests
            {
                [Fact]
                public void Logout_RequiresAntiforgery()
                {
                    Assert.True(typeof(AuthController).HasAttribute<ValidateAntiForgeryToken>());
                }
            }
            """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenEvidenceIsSplitAcrossMultipleTestFiles()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/CsrfEndpointTests.cs",
                "src/OidcStarter.AspNetCore.Bff.Tests/CsrfEndpointTests.cs",
                """
                public class CsrfEndpointTests
                {
                    [Fact]
                    public void CsrfEndpoint_IssuesRequestToken()
                    {
                        var tokens = antiforgery.GetTokens(httpContext);
                        Assert.Equal(tokens.RequestToken, response.Headers["X-XSRF-TOKEN"]);
                        Assert.Equal(StatusCodes.Status204NoContent, response.StatusCode);
                    }
                }
                """),
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryValidationTests.cs",
                "src/OidcStarter.AspNetCore.Bff.Tests/AntiforgeryValidationTests.cs",
                """
                public class AntiforgeryValidationTests
                {
                    [Fact]
                    public void MissingAntiforgeryToken_ReturnsBadRequest()
                    {
                        antiforgery.ValidateRequestAsync(httpContext);
                        Assert.IsType<BadRequestResult>(result);
                    }
                }
                """));

        var findings = new AntiforgeryBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
