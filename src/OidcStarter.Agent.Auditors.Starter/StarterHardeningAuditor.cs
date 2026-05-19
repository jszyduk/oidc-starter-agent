using OidcStarter.Agent.Auditors.Starter.Rules;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter;

public sealed class StarterHardeningAuditor : IAuditor
{
    private readonly IReadOnlyList<IAuditRule> _rules;

    public StarterHardeningAuditor()
        : this(
        [
            new LoginEndpointExistsRule(),
            new LogoutEndpointExistsRule(),
            new MeEndpointExistsRule(),
            new LogoutClearsLocalSessionRule(),
            new OidcIdentityProviderLogoutAwarenessRule(),
            new AuthenticationCookieHttpOnlyRule(),
            new AuthenticationCookieSecurePolicyRule(),
            new AuthenticationCookieSameSiteRule(),
            new AuthenticationCookieLifetimeRule(),
            new AuthenticationCookieSlidingExpirationRule(),
            new AuthenticationCookieNameRule(),
            new BffAntiforgeryFlowRule(),
            new UnsafeHttpMethodsAntiforgeryCoverageRule(),
            new AspNetAuthenticationAuthorizationMiddlewareOrderRule(),
            new AuthorizationFoundationRule(),
            new RoleClaimMappingTestCoverageRule(),
            new SampleRoleMappingDocumentationRule(),
            new NoTokenStorageInFrontendRule(),
            new BffFrontendUsesBackendSessionRule(),
            new KeycloakSetupExistsRule(),
            new BackendTestsExistRule(),
            new AuthEndpointBehaviorTestsRule(),
            new ReadmeExistsRule(),
            new ProductionHardeningDocumentationRule(),
            new BffAuthEndpointsShouldUseControllersRule()
        ])
    {
    }

    public StarterHardeningAuditor(IReadOnlyList<IAuditRule> rules)
    {
        _rules = rules;
    }

    public string Name => "OidcStarter Starter Hardening Auditor";

    public AuditResult Run(RepositorySnapshot snapshot)
    {
        var findings = _rules.SelectMany(rule => rule.Evaluate(snapshot)).ToList();
        return new AuditResult(Name, findings);
    }
}
