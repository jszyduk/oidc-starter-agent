using System.Text;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening;

public sealed class MarkdownReportWriter
{
    public void Write(AuditResult result, string outputPath)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            throw new ArgumentException("Output path is required.", nameof(outputPath));
        }

        var fullOutputPath = Path.GetFullPath(outputPath);
        var outputDirectory = Path.GetDirectoryName(fullOutputPath);
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        File.WriteAllText(fullOutputPath, Build(result));
    }

    public string Build(AuditResult result)
    {
        var builder = new StringBuilder();

        builder.AppendLine("# OidcStarter Hardening Audit Report");
        builder.AppendLine();
        builder.AppendLine($"- Auditor: {result.AuditorName}");
        builder.AppendLine($"- Generated: {DateTimeOffset.UtcNow:O}");
        builder.AppendLine();
        builder.AppendLine("## Summary");
        builder.AppendLine();

        foreach (var severity in OrderedSeverities())
        {
            var count = result.Findings.Count(finding => finding.Severity == severity);
            builder.AppendLine($"- {severity}: {count}");
        }

        builder.AppendLine();
        builder.AppendLine("## Findings");
        builder.AppendLine();

        if (result.Findings.Count == 0)
        {
            builder.AppendLine("No findings.");
            builder.AppendLine();
        }
        else
        {
            foreach (var severity in OrderedSeverities())
            {
                var findings = result.Findings
                    .Where(finding => finding.Severity == severity)
                    .OrderBy(finding => finding.RuleId, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                if (findings.Count == 0)
                {
                    continue;
                }

                builder.AppendLine($"### {severity}");
                builder.AppendLine();

                foreach (var finding in findings)
                {
                    builder.AppendLine($"#### {finding.RuleId}: {finding.Title}");
                    builder.AppendLine();
                    builder.AppendLine($"- Severity: {finding.Severity}");

                    if (!string.IsNullOrWhiteSpace(finding.FilePath))
                    {
                        builder.AppendLine($"- File: `{finding.FilePath}`");
                    }

                    builder.AppendLine($"- Description: {finding.Description}");
                    builder.AppendLine($"- Recommendation: {finding.Recommendation}");
                    builder.AppendLine();
                }
            }
        }

        builder.AppendLine("## Recommendations");
        builder.AppendLine();

        var recommendations = result.Findings
            .Select(finding => finding.Recommendation)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (recommendations.Count == 0)
        {
            builder.AppendLine("- Continue running the hardening audit as part of release readiness checks.");
        }
        else
        {
            foreach (var recommendation in recommendations)
            {
                builder.AppendLine($"- {recommendation}");
            }
        }

        return builder.ToString();
    }

    private static FindingSeverity[] OrderedSeverities()
    {
        return
        [
            FindingSeverity.Critical,
            FindingSeverity.High,
            FindingSeverity.Medium,
            FindingSeverity.Low,
            FindingSeverity.Info
        ];
    }
}
