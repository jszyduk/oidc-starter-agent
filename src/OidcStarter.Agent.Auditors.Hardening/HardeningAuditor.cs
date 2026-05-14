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
            new LogoutClearsLocalSessionRule(),
            new AuthenticationCookieHttpOnlyRule(),
            new AuthenticationCookieSecurePolicyRule(),
            new AuthenticationCookieSameSiteRule(),
            new BffAntiforgeryFlowRule(),
            new AspNetAuthenticationAuthorizationMiddlewareOrderRule(),
            new NoTokenStorageInFrontendRule(),
            new BffFrontendUsesBackendSessionRule(),
            new KeycloakSetupExistsRule(),
            new BackendTestsExistRule(),
            new ReadmeExistsRule(),
            new ProductionHardeningDocumentationRule(),
            new BffAuthEndpointsShouldUseControllersRule()
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
