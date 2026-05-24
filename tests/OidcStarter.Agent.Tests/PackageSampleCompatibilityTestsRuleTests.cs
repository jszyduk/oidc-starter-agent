using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class PackageSampleCompatibilityTestsRuleTests
{
    private const string TestRepositoryRoot = "/repo";

    [Fact]
    public void ReturnsNoFinding_WhenWebApplicationFactoryExercisesSampleBackend()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SampleBackendCompatibilityTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SampleBackendCompatibilityTests.cs",
            """
            public class SampleBackendCompatibilityTests
            {
                [Fact]
                public async Task MeEndpoint_Uses_Local_Bff_Package_In_Sample_Backend()
                {
                    await using var factory = new WebApplicationFactory<Program>();
                    var client = factory.CreateClient();
                    var response = await client.GetAsync("/api/auth/me");
                    Assert.NotNull(response);
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenNamedCompatibilityTestHasNoConcreteSignal()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/PackageSampleCompatibilityTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/PackageSampleCompatibilityTests.cs",
            """
            public class PackageSampleCompatibilityTests
            {
                [Fact]
                public void Boots_Sample_Backend_With_Local_Bff_Package()
                {
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenNamedCompatibilityTestUsesWebApplicationFactory()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/PackageSampleCompatibilityTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/PackageSampleCompatibilityTests.cs",
            """
            public class PackageSampleCompatibilityTests
            {
                [Fact]
                public void Boots_Sample_Backend_With_Local_Bff_Package()
                {
                    using var factory = new WebApplicationFactory<Program>();
                    var client = factory.CreateClient();
                    Assert.NotNull(client);
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCreateClientHasNoPackageSampleContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/ClientFactoryTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/ClientFactoryTests.cs",
            """
            public class ClientFactoryTests
            {
                [Fact]
                public void Creates_Client()
                {
                    var client = factory.CreateClient();
                    Assert.NotNull(client);
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenWebApplicationFactoryHasNoCompatibilityContext()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "tests/UnrelatedWebHostTests.cs",
            "tests/UnrelatedWebHostTests.cs",
            """
            public class UnrelatedWebHostTests
            {
                [Fact]
                public void Host_Starts()
                {
                    using var factory = new WebApplicationFactory<Program>();
                    Assert.NotNull(factory);
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlySampleProjectReferencesPackage()
    {
        var snapshot = Snapshot(BackendProjectReference());

        var finding = Assert.Single(new PackageSampleCompatibilityTestsRule().Evaluate(snapshot));

        Assert.Equal("HARDENING-028", finding.RuleId);
    }

    [Fact]
    public void ReturnsNoFinding_WhenSolutionBuildsSampleAndPackageWithProjectReference()
    {
        var snapshot = Snapshot(
            BackendProjectReference(),
            new RepositoryFile(
                "OidcStarter.sln",
                "OidcStarter.sln",
                """
                Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Backend", "src\Backend\Backend.csproj", "{11111111-1111-1111-1111-111111111111}"
                EndProject
                Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "OidcStarter.AspNetCore.Bff", "src\OidcStarter.AspNetCore.Bff\OidcStarter.AspNetCore.Bff.csproj", "{22222222-2222-2222-2222-222222222222}"
                EndProject
                """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenTestProjectMsBuildTargetBuildsBackendWithProjectReference()
    {
        var snapshot = Snapshot(
            BackendProjectReference(),
            new RepositoryFile(
                "src/OidcStarter.AspNetCore.Bff.Tests/OidcStarter.AspNetCore.Bff.Tests.csproj",
                "src/OidcStarter.AspNetCore.Bff.Tests/OidcStarter.AspNetCore.Bff.Tests.csproj",
                """
                <Project Sdk="Microsoft.NET.Sdk">
                  <Target Name="BuildSampleBackend" BeforeTargets="Test">
                    <MSBuild Projects="..\backend\Backend.csproj" Targets="Build" Properties="Configuration=$(Configuration)" />
                  </Target>
                </Project>
                """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyPackageTestsExist()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SomePackageTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SomePackageTests.cs",
            """
            public class SomePackageTests
            {
                [Fact]
                public void Package_Service_Works()
                {
                    Assert.True(true);
                }
            }
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlySampleBackendExists()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/Backend/Backend.csproj",
                "src/Backend/Backend.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>"),
            new RepositoryFile(
                "src/Backend/Program.cs",
                "src/Backend/Program.cs",
                "var builder = WebApplication.CreateBuilder(args);"));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenOnlyDocsMentionCompatibility()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "README.md",
            "README.md",
            "The package and sample are compatible."));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCompatibilityEvidenceOnlyAppearsInCommentsAndRawStrings()
    {
        var snapshot = Snapshot(new RepositoryFile(
            "src/OidcStarter.AspNetCore.Bff.Tests/SampleBackendCompatibilityTests.cs",
            "src/OidcStarter.AspNetCore.Bff.Tests/SampleBackendCompatibilityTests.cs",
            "public class SampleBackendCompatibilityTests\r\n{\r\n// WebApplicationFactory<Program>\r\n// PackageSampleCompatibilityTests\r\nvar sample = \"\"\"\r\n[Fact]\r\npublic async Task Boots_Sample_Backend_With_Local_Bff_Package() { new WebApplicationFactory<Program>().CreateClient(); }\r\n\"\"\";\r\n}"));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenProjectReferenceIsCommentedOut()
    {
        var snapshot = Snapshot(
            new RepositoryFile(
                "src/Backend/Backend.csproj",
                "src/Backend/Backend.csproj",
                """
                <Project Sdk="Microsoft.NET.Sdk.Web">
                  <ItemGroup>
                    <!-- <ProjectReference Include="..\OidcStarter.AspNetCore.Bff\OidcStarter.AspNetCore.Bff.csproj" /> -->
                  </ItemGroup>
                </Project>
                """),
            new RepositoryFile(
                "OidcStarter.sln",
                "OidcStarter.sln",
                """
                Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Backend", "src\Backend\Backend.csproj", "{11111111-1111-1111-1111-111111111111}"
                EndProject
                Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "OidcStarter.AspNetCore.Bff", "src\OidcStarter.AspNetCore.Bff\OidcStarter.AspNetCore.Bff.csproj", "{22222222-2222-2222-2222-222222222222}"
                EndProject
                """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCiBuildEvidenceIsCommentedOut()
    {
        var snapshot = Snapshot(
            BackendProjectReference(),
            new RepositoryFile(
                ".github/workflows/ci.yml",
                ".github/workflows/ci.yml",
                """
                name: ci
                jobs:
                  build:
                    steps:
                      # dotnet build OidcStarter.sln
                      # dotnet test OidcStarter.sln
                """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    [Fact]
    public void ReturnsNoFinding_WhenCiBuildsBothProjectsWithProjectReference()
    {
        var snapshot = Snapshot(
            BackendProjectReference(),
            new RepositoryFile(
                ".github/workflows/ci.yml",
                ".github/workflows/ci.yml",
                """
                name: ci
                jobs:
                  build:
                    steps:
                      - run: dotnet build ./src/OidcStarter.AspNetCore.Bff/OidcStarter.AspNetCore.Bff.csproj
                      - run: dotnet build ./src/Backend/Backend.csproj
                      - run: dotnet test ./OidcStarter.sln
                """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Empty(findings);
    }

    [Fact]
    public void ReturnsFinding_WhenCiMentionsBuildWithoutSampleProjectReference()
    {
        var snapshot = Snapshot(new RepositoryFile(
            ".github/workflows/ci.yml",
            ".github/workflows/ci.yml",
            """
            name: ci
            jobs:
              build:
                steps:
                  - run: dotnet build ./OidcStarter.sln
                  - run: dotnet test ./OidcStarter.sln
            """));

        var findings = new PackageSampleCompatibilityTestsRule().Evaluate(snapshot);

        Assert.Single(findings);
    }

    private static RepositoryFile BackendProjectReference()
    {
        return new RepositoryFile(
            "src/Backend/Backend.csproj",
            "src/Backend/Backend.csproj",
            """
            <Project Sdk="Microsoft.NET.Sdk.Web">
              <ItemGroup>
                <ProjectReference Include="..\OidcStarter.AspNetCore.Bff\OidcStarter.AspNetCore.Bff.csproj" />
              </ItemGroup>
            </Project>
            """);
    }

    private static RepositorySnapshot Snapshot(params RepositoryFile[] files)
    {
        return new RepositorySnapshot(TestRepositoryRoot, files);
    }
}
