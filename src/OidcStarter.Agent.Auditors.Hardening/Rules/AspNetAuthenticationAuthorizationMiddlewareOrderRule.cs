using OidcStarter.Agent.Auditors.Hardening.Detection;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Hardening.Rules;

public sealed class AspNetAuthenticationAuthorizationMiddlewareOrderRule : HardeningRuleBase
{
    private const string Recommendation =
        "Baseline ASPNET-HOST-001: register authentication middleware before authorization middleware in the ASP.NET Core request pipeline, for example app.UseAuthentication(); before app.UseAuthorization().";

    public override string RuleId => "HARDENING-014";

    public override string Title => "ASP.NET Core authentication/authorization middleware order may be invalid";

    public override IReadOnlyList<AuditFinding> Evaluate(RepositorySnapshot snapshot)
    {
        return AspNetMiddlewareDetector.GetAuthenticationAuthorizationOrderIssue(snapshot) switch
        {
            AspNetMiddlewareDetector.AuthenticationAuthorizationOrderIssue.AuthorizationWithoutAuthentication =>
            [
                Finding(
                    FindingSeverity.High,
                    "UseAuthorization was detected in a likely ASP.NET Core pipeline, but no UseAuthentication call was detected.",
                    Recommendation)
            ],
            AspNetMiddlewareDetector.AuthenticationAuthorizationOrderIssue.AuthorizationBeforeAuthentication =>
            [
                Finding(
                    FindingSeverity.High,
                    "UseAuthorization appears before UseAuthentication in a likely ASP.NET Core pipeline.",
                    Recommendation)
            ],
            AspNetMiddlewareDetector.AuthenticationAuthorizationOrderIssue.DifferentFilesOrContexts =>
            [
                Finding(
                    FindingSeverity.High,
                    "UseAuthentication and UseAuthorization were found in different files or contexts, so middleware order could not be verified.",
                    Recommendation)
            ],
            _ => []
        };
    }
}
