using OidcStarter.Agent.Auditors.Hardening;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Tests;

public sealed class MarkdownReportWriterTests
{
    [Fact]
    public void Build_IncludesProblemOrientedTitleAndLabeledFindingDetails()
    {
        var result = new AuditResult(
            "Test Auditor",
            [
                new AuditFinding(
                    "HARDENING-013",
                    "No explicit authentication cookie SameSite configuration detected",
                    FindingSeverity.Medium,
                    "No likely authentication cookie SameSite configuration was detected.",
                    null,
                    "Baseline BFF-COOKIE-003: configure SameSite intentionally.")
            ]);

        var markdown = new MarkdownReportWriter().Build(result);

        Assert.Contains("#### HARDENING-013: No explicit authentication cookie SameSite configuration detected", markdown);
        Assert.Contains("- Severity: Medium", markdown);
        Assert.Contains("- Description: No likely authentication cookie SameSite configuration was detected.", markdown);
        Assert.Contains("- Recommendation: Baseline BFF-COOKIE-003: configure SameSite intentionally.", markdown);
    }
}
