namespace OidcStarter.Agent.Tests;

public sealed class CliOptionsTests
{
    [Fact]
    public void Parse_ReturnsStarterAuditType_WhenAuditStarterIsUsed()
    {
        var options = CliOptions.Parse(["audit", "starter", "--repo", "."]);

        Assert.Equal("starter", options.AuditType);
    }

    [Fact]
    public void Parse_ReturnsStarterAuditType_WhenAuditHardeningAliasIsUsed()
    {
        var options = CliOptions.Parse(["audit", "hardening", "--repo", "."]);

        Assert.Equal("starter", options.AuditType);
    }

    [Fact]
    public void Parse_ThrowsUsefulError_WhenAuditTypeIsUnknown()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            CliOptions.Parse(["audit", "consumer", "--repo", "."]));

        Assert.Contains("Unknown audit type 'consumer'. Supported audit types: starter, hardening.", exception.Message);
    }
}
