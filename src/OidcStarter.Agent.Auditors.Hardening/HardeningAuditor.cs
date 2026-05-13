using OidcStarter.Agent.Auditors.Hardening.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening;

public sealed class HardeningAuditor : IAuditor
{
    private readonly IReadOnlyList<IAuditRule> _rules;

    public HardeningAuditor()
        : this(
        [
            new LoginEndpointExistsRule(),
            new LogoutEndpointExistsRule(),
            new MeEndpointExistsRule(),
            new AntiforgeryMentionedRule(),
            new NoTokenStorageInFrontendRule(),
            new KeycloakSetupExistsRule(),
            new BackendTestsExistRule(),
            new ReadmeExistsRule()
        ])
    {
    }

    public HardeningAuditor(IReadOnlyList<IAuditRule> rules)
    {
        _rules = rules;
    }

    public string Name => "OidcStarter Hardening Auditor";

    public AuditResult Run(RepositorySnapshot snapshot)
    {
        var findings = _rules.SelectMany(rule => rule.Evaluate(snapshot)).ToList();
        return new AuditResult(Name, findings);
    }
}
