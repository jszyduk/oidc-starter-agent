using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Rules;

public sealed class NoTokenStorageInFrontendRule : HardeningRuleBase
{
    private static readonly string[] StorageTerms = ["localStorage", "sessionStorage"];
    private static readonly string[] TokenTerms = ["token", "access_token", "id_token", "refresh_token"];

    public override string RuleId => "HARDENING-005";

    public override string Title => "Suspicious browser token storage detected";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return snapshot.Files
            .Where(file => file.RelativePath.EndsWith(".ts", StringComparison.OrdinalIgnoreCase))
            .Where(HasSuspiciousTokenStorage)
            .Select(file => Finding(
                FindingSeverity.Critical,
                "Suspicious frontend token storage pattern found.",
                "Avoid storing OIDC tokens in browser localStorage or sessionStorage. Prefer cookie-backed BFF session handling.",
                file.RelativePath))
            .ToList();
    }

    private static bool HasSuspiciousTokenStorage(RepositoryFile file)
    {
        return StorageTerms.Any(storage => file.Content.Contains(storage, StringComparison.OrdinalIgnoreCase))
            && TokenTerms.Any(token => file.Content.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
}
