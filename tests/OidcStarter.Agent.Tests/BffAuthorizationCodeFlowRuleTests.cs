using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class BffAuthorizationCodeFlowRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenPackageUsesOpenIdConnectResponseTypeCode()
    {
        var snapshot = Snapshot(PackageFile(
            """
            public static class OidcStarterBffServiceCollectionExtensions
            {
                public static IServiceCollection AddBff(this IServiceCollection services)
                {
                    services.AddAuthentication()
                        .AddOpenIdConnect(options =>
                        {
                            options.ResponseType = OpenIdConnectResponseType.Code;
                        });

                    return services;
                }
            }
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenPackageUsesStringCodeResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "code";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOpenIdConnectConfigOmitsResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.Authority = authority;
                });
            """));

        var finding = Assert.Single(new BffAuthorizationCodeFlowRule().Evaluate(snapshot));

        Assert.Equal("HARDENING-030", finding.RuleId);
    }

    [Fact]
    public void ReturnsFinding_WhenConstResponseTypeCodeIsOutsideOpenIdConnectOptions()
    {
        var snapshot = Snapshot(PackageFile(
            """
            const string ResponseType = "code";

            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.Authority = "https://idp";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenUnrelatedMetadataHasCodeResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            var metadata = new { ResponseType = "code" };

            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.Authority = "https://idp";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenAuthorizationCodeReceivedEventExistsWithoutResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.Events.OnAuthorizationCodeReceived = context => Task.CompletedTask;
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenConfigureOpenIdConnectOptionsUsesStringCode()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.Configure<OpenIdConnectOptions>(options =>
            {
                options.ResponseType = "code";
            });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesImplicitIdTokenResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "id_token";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesImplicitIdTokenTokenResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "id_token token";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesHybridCodeIdTokenResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "code id_token";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesHybridCodeTokenResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "code token";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesTokenResponseType()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "token";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesIdTokenConstant()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.IdToken;
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesIdTokenTokenConstant()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.IdTokenToken;
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesCodeIdTokenConstant()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageUsesCodeTokenConstant()
    {
        var snapshot = Snapshot(PackageFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.CodeToken;
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyCommentsAndRawStringsMentionResponseTypes()
    {
        var snapshot = Snapshot(PackageFile(
            """""
            public static class OidcConfig
            {
                // options.ResponseType = "code";
                // options.ResponseType = "id_token";

                public static string Sample = """
                services.AddAuthentication()
                    .AddOpenIdConnect(options =>
                    {
                        options.ResponseType = "code";
                        options.ResponseType = "id_token";
                    });
                """;
            }
            """""));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyTestsContainCodeFlowConfig()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/OidcOptionsTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/OidcOptionsTests.cs",
            """
            public class OidcOptionsTests
            {
                [Fact]
                public void UsesCodeFlow()
                {
                    options.ResponseType = OpenIdConnectResponseType.Code;
                }
            }
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyFrontendConfigMentionsResponseType()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/frontend/src/environments/environment.ts",
            "src/frontend/src/environments/environment.ts",
            """
            export const environment = {
                responseType: 'code',
                legacyResponseType: 'id_token'
            };
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenPackageIsMissingCodeFlowEvenIfSampleIsCorrect()
    {
        var snapshot = Snapshot(
            PackageFile(
                """
                services.AddAuthentication()
                    .AddOpenIdConnect(options =>
                    {
                        options.Authority = authority;
                    });
                """),
            SampleFile(
                """
                services.AddAuthentication()
                    .AddOpenIdConnect(options =>
                    {
                        options.ResponseType = "code";
                    });
                """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenSampleBackendUsesCodeFlowAndNoPackageExists()
    {
        var snapshot = Snapshot(SampleFile(
            """
            services.AddAuthentication()
                .AddOpenIdConnect(options =>
                {
                    options.ResponseType = "code";
                });
            """));

        var findings = new BffAuthorizationCodeFlowRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    private static RepositoryFile PackageFile(string content)
    {
        return new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            "src/OidcStarter.AspNetCore.Bff/Extensions/OidcStarterBffServiceCollectionExtensions.cs",
            content);
    }

    private static RepositoryFile SampleFile(string content)
    {
        return new RepositoryFile(
            "src/Backend/Program.cs",
            "src/Backend/Program.cs",
            content);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
