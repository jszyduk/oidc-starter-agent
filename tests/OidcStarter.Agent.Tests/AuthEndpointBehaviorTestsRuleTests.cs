using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class AuthEndpointBehaviorTestsRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenAllThreeBehaviorsHaveFocusedTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Login_ReturnsChallenge()
                {
                    var result = controller.Login();
                    Assert.IsType<ChallengeResult>(result);
                }

                [Fact]
                public void Logout_ReturnsSignOutResult()
                {
                    var result = controller.Logout();
                    Assert.IsType<SignOutResult>(result);
                }

                [Fact]
                public void Me_ReturnsCurrentUserClaims()
                {
                    var result = controller.Me();
                    Assert.Contains(result.Claims, claim => claim.Type == ClaimTypes.Name);
                }
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
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

        var finding = Assert.Single(new AuthEndpointBehaviorTestsRule().Evaluate(snapshot));

        Assert.Equal("HARDENING-025", finding.RuleId);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyMethodNamesMentionBehaviorTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Login_ReturnsChallenge()
                {
                }

                [Fact]
                public void Logout_ReturnsSignOutResult()
                {
                }

                [Fact]
                public void Me_ReturnsCurrentUserClaims()
                {
                }
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyRouteStringsMentionAuthEndpoints()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Route_Constants_Are_Not_Behavior_Evidence()
                {
                    var routes = new[]
                    {
                        "/api/auth/login",
                        "/api/auth/logout",
                        "/api/auth/me"
                    };
                }
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenFakeBehaviorTestsOnlyAppearInRawString()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "var sample = \"\"\"\r\n[Fact]\r\npublic void Login_ReturnsChallenge() { Assert.IsType<ChallengeResult>(result); }\r\n\r\n[Fact]\r\npublic void Logout_ReturnsSignOutResult() { Assert.IsType<SignOutResult>(result); }\r\n\r\n[Fact]\r\npublic void Me_ReturnsCurrentUserClaims() { Assert.Contains(claims, c => c.Type == ClaimTypes.Name); }\r\n\"\"\";"));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFindingMentioningLogin_WhenLoginEvidenceIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Logout_ReturnsSignOutResult()
                {
                    Assert.IsType<SignOutResult>(controller.Logout());
                }

                [Fact]
                public void Me_ReturnsCurrentUserClaims()
                {
                    Assert.Contains(controller.Me().Claims, claim => claim.Type == ClaimTypes.Name);
                }
            }
            """));

        var finding = Assert.Single(new AuthEndpointBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("login", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFinding_WhenLogoutEvidenceIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Login_ReturnsChallenge()
                {
                    Assert.IsType<ChallengeResult>(controller.Login());
                }

                [Fact]
                public void Me_ReturnsCurrentUserClaims()
                {
                    Assert.Contains(controller.Me().Claims, claim => claim.Type == ClaimTypes.Name);
                }
            }
            """));

        var finding = Assert.Single(new AuthEndpointBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("logout", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFinding_WhenMeEvidenceIsMissing()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Login_ReturnsChallenge()
                {
                    Assert.IsType<ChallengeResult>(controller.Login());
                }

                [Fact]
                public void Logout_ReturnsSignOutResult()
                {
                    Assert.IsType<SignOutResult>(controller.Logout());
                }
            }
            """));

        var finding = Assert.Single(new AuthEndpointBehaviorTestsRule().Evaluate(snapshot));

        Assert.Contains("me/current-user", finding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyProductionControllerHasAuthMethods()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            "src/OidcStarter.AspNetCore.Bff/AuthController.cs",
            """
            public class AuthController
            {
                public IActionResult Login() => Challenge();
                public IActionResult Logout() => SignOut();
                public IActionResult Me() => Ok(User.Claims);
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyCommentsMentionBehaviorTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                // Login_ReturnsChallenge
                // Logout_ReturnsSignOutResult
                // Me_ReturnsCurrentUserClaims
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyDocsMentionBehaviorTests()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "README.md",
            "README.md",
            "The BFF has login/logout/me tests."));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenRouteStringsHaveAssertionEvidence()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthEndpointRouteTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthEndpointRouteTests.cs",
            """
            public class AuthEndpointRouteTests
            {
                [Fact]
                public async Task Auth_Endpoints_Return_Expected_Behavior()
                {
                    var loginResponse = await client.GetAsync("/api/auth/login");
                    Assert.Equal(HttpStatusCode.Redirect, loginResponse.StatusCode);

                    var logoutResponse = await client.PostAsync("/api/auth/logout", content: null);
                    Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

                    var meResponse = await client.GetAsync("/api/auth/me");
                    Assert.True(meResponse.User.Identity.IsAuthenticated);
                }
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyUnrelatedVariableNamesExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/AuthControllerTests.cs",
            """
            public class AuthControllerTests
            {
                [Fact]
                public void Names_Are_Not_Behavior_Evidence()
                {
                    var login = "login";
                    var logout = "logout";
                    var me = "me";
                    Assert.NotNull(login + logout + me);
                }
            }
            """));

        var findings = new AuthEndpointBehaviorTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
