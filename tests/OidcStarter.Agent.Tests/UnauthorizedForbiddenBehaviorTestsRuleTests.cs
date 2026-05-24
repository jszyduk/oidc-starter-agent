using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class UnauthorizedForbiddenBehaviorTestsRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenUnauthorizedAndForbiddenEvidenceExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void AnonymousUser_ReturnsUnauthorized()
                {
                    Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
                }

                [Fact]
                public void UserWithoutRequiredRole_ReturnsForbidden()
                {
                    Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
                }
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFindingMentioningForbidden_WhenOnlyUnauthorizedEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void AnonymousUser_ReturnsUnauthorized()
                {
                    Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFindingMentioningUnauthorized_WhenOnlyForbiddenEvidenceExists()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void UserWithoutRequiredRole_ReturnsForbidden()
                {
                    Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
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

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyProductionCodeHasAuthorizationFailures()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Authorization/SecureController.cs",
            "src/OidcStarter.AspNetCore.Bff/Authorization/SecureController.cs",
            """
            public class SecureController
            {
                public IActionResult Anonymous() => new UnauthorizedResult();
                public IActionResult WrongRole() => new ForbidResult();
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyCommentsMentionAuthorizationFailureTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                // AnonymousUser_ReturnsUnauthorized
                // UserWithoutRole_ReturnsForbidden
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenFakeTestsOnlyAppearInRawString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "var sample = \"\"\"\r\n[Fact]\r\npublic void NotLoggedIn_ReturnsUnauthorized() { Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode); }\r\n\r\n[Fact]\r\npublic void AccessDenied_ReturnsForbidden() { Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode); }\r\n\"\"\";"));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyDocsMentionAuthorizationFailureTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "README.md",
            "README.md",
            "Unauthorized and forbidden tests cover 401 and 403 responses."));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyStatusConstantsExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void Constants_Are_Not_Behavior_Evidence()
                {
                    var unauthorized = StatusCodes.Status401Unauthorized;
                    var forbidden = StatusCodes.Status403Forbidden;
                    Assert.True(unauthorized < forbidden);
                }
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenEvidenceIsSplitAcrossMultipleTestFiles()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/UnauthorizedBehaviorTests.cs",
                "src/OidcStarter.AspNetCore.Bff.Tests/UnauthorizedBehaviorTests.cs",
                """
                public class UnauthorizedBehaviorTests
                {
                    [Fact]
                    public void AnonymousUser_ReturnsUnauthorized()
                    {
                        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                    }
                }
                """),
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/ForbiddenBehaviorTests.cs",
                "src/OidcStarter.AspNetCore.Bff.Tests/ForbiddenBehaviorTests.cs",
                """
                public class ForbiddenBehaviorTests
                {
                    [Fact]
                    public void UserWithoutRequiredRole_ReturnsForbidden()
                    {
                        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
                    }
                }
                """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenCookieAuthEventForbiddenEvidenceContainsUrlLiteral()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/Extensions/OidcStarterBffServiceCollectionExtensionsTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/Extensions/OidcStarterBffServiceCollectionExtensionsTests.cs",
            """
            public sealed class OidcStarterBffServiceCollectionExtensionsTests
            {
                [Fact]
                public async Task Cookie_authentication_OnRedirectToLogin_returns_401_for_api_request()
                {
                    var context = CreateRedirectContext("https://api.example.com/api/auth/me");
                    var events = new CookieAuthenticationEvents();

                    await events.OnRedirectToLogin(context);

                    Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
                }

                [Fact]
                public async Task Cookie_authentication_OnRedirectToAccessDenied_returns_403_for_api_request()
                {
                    var context = CreateRedirectContext("https://api.example.com/api/admin/users");
                    var events = new CookieAuthenticationEvents();

                    await events.OnRedirectToAccessDenied(context);

                    Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
                }
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenChallengeResultHasNoAnonymousContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void ReturnsChallenge()
                {
                    Assert.IsType<ChallengeResult>(result);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFindingMentioningForbidden_WhenChallengeResultHasAnonymousContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void AnonymousUser_ReturnsChallenge()
                {
                    Assert.IsType<ChallengeResult>(result);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFinding_WhenForbidResultHasNoAuthorizationContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void ReturnsForbid()
                {
                    Assert.IsType<ForbidResult>(result);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFindingMentioningUnauthorized_WhenForbidResultHasRoleContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void UserWithoutRequiredRole_ReturnsForbid()
                {
                    Assert.IsType<ForbidResult>(result);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFindingMentioningForbidden_WhenNotLoggedInOnlyCoversUnauthorizedCategory()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void NotLoggedIn_ReturnsUnauthorized()
                {
                    Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFindingMentioningUnauthorized_WhenAccessDeniedOnlyCoversForbiddenCategory()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void AccessDenied_ReturnsForbidden()
                {
                    Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
                }
            }
            """));

        var finding = Assert.Single(new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("unauthorized", finding.Description, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("forbidden", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsNoFinding_WhenNotLoggedInAndAccessDeniedEvidenceExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthorizationBehaviorTests.cs",
            """
            public class AuthorizationBehaviorTests
            {
                [Fact]
                public void NotLoggedIn_ReturnsUnauthorized()
                {
                    Assert.Equal(StatusCodes.Status401Unauthorized, response.StatusCode);
                }

                [Fact]
                public void AccessDenied_ReturnsForbidden()
                {
                    Assert.Equal(StatusCodes.Status403Forbidden, response.StatusCode);
                }
            }
            """));

        var findings = new UnauthorizedForbiddenBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
