using OidcStarter.Agent.Auditors.Starter;

return ProgramRunner.Run(args);

internal static class ProgramRunner
{
    public static int Run(string[] args)
    {
        try
        {
            var options = CliOptions.Parse(args);

            if (!Directory.Exists(options.RepositoryPath))
            {
                Console.Error.WriteLine($"Repository path does not exist: {options.RepositoryPath}");
                return 1;
            }

            var scanner = new RepositoryScanner();
            var snapshot = scanner.Scan(options.RepositoryPath);
            var auditor = new StarterHardeningAuditor();
            var result = auditor.Run(snapshot);

            var outputPath = Path.GetFullPath(options.OutputPath);
            var writer = new MarkdownReportWriter();
            writer.Write(result, outputPath);

            Console.WriteLine($"Report written to: {outputPath}");
            return 0;
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine(exception.Message);
            PrintUsage();
            return 1;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Audit failed: {exception.Message}");
            return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("Usage: dotnet run -- audit hardening --repo \"[FULL_PATH_TO_REPO]\\oidc-starter\" --out \"audit-report.md\"");
    }
}

internal sealed record CliOptions(string RepositoryPath, string OutputPath)
{
    public static CliOptions Parse(string[] args)
    {
        if (args.Length < 4
            || !args[0].Equals("audit", StringComparison.OrdinalIgnoreCase)
            || !args[1].Equals("hardening", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Invalid command. Expected 'audit hardening'.");
        }

        string? repositoryPath = null;
        string outputPath = Path.Combine(Directory.GetCurrentDirectory(), "audit-report.md");

        for (var index = 2; index < args.Length; index++)
        {
            var argument = args[index];
            if (argument.Equals("--repo", StringComparison.OrdinalIgnoreCase))
            {
                repositoryPath = ReadValue(args, ref index, "--repo");
                continue;
            }

            if (argument.Equals("--out", StringComparison.OrdinalIgnoreCase))
            {
                outputPath = ReadValue(args, ref index, "--out");
                continue;
            }

            throw new ArgumentException($"Unknown argument: {argument}");
        }

        if (string.IsNullOrWhiteSpace(repositoryPath))
        {
            throw new ArgumentException("Missing required argument: --repo");
        }

        return new CliOptions(Path.GetFullPath(repositoryPath), outputPath);
    }

    private static string ReadValue(string[] args, ref int index, string optionName)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException($"Missing value for {optionName}");
        }

        index++;
        return args[index];
    }
}
