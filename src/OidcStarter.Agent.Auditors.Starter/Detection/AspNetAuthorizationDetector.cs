using System.Text.RegularExpressions;
using OidcStarter.Agent.Core;

namespace OidcStarter.Agent.Auditors.Starter.Detection;

public static partial class AspNetAuthorizationDetector
{
    public static AuthorizationFoundationResult Inspect(RepositorySnapshot snapshot)
    {
        var packageFiles = snapshot.Files
            .Where(file => StarterRepositoryLayoutDetector.IsProductionStarterCodeFile(file)
                && StarterRepositoryLayoutDetector.IsBffPackageFile(file))
            .ToList();
        var sampleBackendFiles = snapshot.Files
            .Where(file => StarterRepositoryLayoutDetector.IsProductionStarterCodeFile(file)
                && StarterRepositoryLayoutDetector.IsSampleBackendFile(file))
            .ToList();

        var packageSignals = InspectCodeFiles(packageFiles);
        var sampleSignals = InspectCodeFiles(sampleBackendFiles);

        var hasPackageSetup = packageSignals.HasAuthorizationSetup || packageSignals.HasPolicySetup;
        var hasPackageExtensionPoint = packageSignals.HasRoleOrClaimMappingExtensionPoint;
        var hasPackageProtectedEndpoint = packageSignals.HasProtectedEndpoint;
        var hasSampleProtectedEndpoint = sampleSignals.HasProtectedEndpoint;
        var hasPackageMiddleware = packageSignals.HasUseAuthorization;

        var hasPackageFoundationSignal = hasPackageSetup || hasPackageExtensionPoint;
        var hasProtectedUsage = hasPackageProtectedEndpoint || hasSampleProtectedEndpoint;
        var hasFoundation = hasPackageFoundationSignal && hasProtectedUsage;

        var evidencePath = packageSignals.FirstEvidencePath
            ?? sampleSignals.FirstEvidencePath
            ?? packageFiles.FirstOrDefault()?.RelativePath
            ?? sampleBackendFiles.FirstOrDefault()?.RelativePath;

        return new AuthorizationFoundationResult(
            hasFoundation,
            hasPackageSetup,
            packageSignals.HasPolicySetup,
            hasPackageExtensionPoint,
            hasPackageProtectedEndpoint,
            hasSampleProtectedEndpoint,
            hasPackageMiddleware,
            evidencePath);
    }

    private static AuthorizationSignals InspectCodeFiles(IEnumerable<RepositoryFile> files)
    {
        var result = new AuthorizationSignals();

        foreach (var file in files)
        {
            var content = PrepareContent(file.Content);
            var hasAuthorizationSetup = AuthorizationSetupRegex().IsMatch(content);
            var hasPolicySetup = PolicySetupRegex().IsMatch(content);
            var hasRoleOrClaimMappingExtensionPoint = RoleOrClaimMappingExtensionPointRegex().IsMatch(content);
            var hasProtectedEndpoint = AuthorizeAttributeRegex().IsMatch(content);
            var hasUseAuthorization = UseAuthorizationRegex().IsMatch(content);

            result.HasAuthorizationSetup |= hasAuthorizationSetup;
            result.HasPolicySetup |= hasPolicySetup;
            result.HasRoleOrClaimMappingExtensionPoint |= hasRoleOrClaimMappingExtensionPoint;
            result.HasProtectedEndpoint |= hasProtectedEndpoint;
            result.HasUseAuthorization |= hasUseAuthorization;

            if (result.FirstEvidencePath is null
                && (hasAuthorizationSetup
                    || hasPolicySetup
                    || hasRoleOrClaimMappingExtensionPoint
                    || hasProtectedEndpoint
                    || hasUseAuthorization))
            {
                result.FirstEvidencePath = file.RelativePath;
            }
        }

        return result;
    }

    private static string PrepareContent(string content)
    {
        var withoutBlockComments = BlockCommentRegex().Replace(content, string.Empty);
        var withoutLineComments = LineCommentRegex().Replace(withoutBlockComments, string.Empty);
        var withoutRawStrings = RawStringLiteralRegex().Replace(withoutLineComments, "STRING_LITERAL");
        var withoutVerbatimStrings = VerbatimStringLiteralRegex().Replace(withoutRawStrings, "STRING_LITERAL");
        return RegularStringLiteralRegex().Replace(withoutVerbatimStrings, "STRING_LITERAL");
    }

    [GeneratedRegex(@"\b(?:builder\.Services\.|services\.)?(?:AddAuthorization(?:Builder)?|AddOidcStarterAuthorization)\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationSetupRegex();

    [GeneratedRegex(@"\b(?:options\.)?AddPolicy\s*\(|\bAuthorizationPolicyBuilder\b|\bRequireRole\s*\(|\bRequireClaim\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PolicySetupRegex();

    [GeneratedRegex(@"\bIClaimsTransformation\b|\bIAuthorizationRequirement\b|\bAuthorizationHandler(?:<|\b)|\b\w*OidcStarter\w*(?:Role|Claim)s?Mapper\b|\b(?:I)?(?:Auth|Authorization)\w*(?:Role|Claim)s?Mapper\b|\b\w*ClaimsTransformer\b|\bMapRoles\s*\(|\bMapClaims\s*\(|\btoken\s*validation\s*claim\s*mapp(?:er|ing)?\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RoleOrClaimMappingExtensionPointRegex();

    [GeneratedRegex(@"\[\s*Authorize(?:Attribute)?(?:\s*\([^\)]*\))?\s*\]|\.\s*RequireAuthorization\s*\((?:[^\)]*)\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizeAttributeRegex();

    [GeneratedRegex(@"\bapp\.UseAuthorization\s*\(", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UseAuthorizationRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline | RegexOptions.CultureInvariant)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"//.*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LineCommentRegex();

    [GeneratedRegex(@"\$*""""""[\s\S]*?""""""", RegexOptions.CultureInvariant)]
    private static partial Regex RawStringLiteralRegex();

    [GeneratedRegex(@"(?:\$@|@\$|@)""(?:""""|[^""])*""", RegexOptions.CultureInvariant)]
    private static partial Regex VerbatimStringLiteralRegex();

    [GeneratedRegex(@"\$?""(?:\\.|[^""\\])*""", RegexOptions.CultureInvariant)]
    private static partial Regex RegularStringLiteralRegex();

    private sealed class AuthorizationSignals
    {
        public bool HasAuthorizationSetup { get; set; }

        public bool HasPolicySetup { get; set; }

        public bool HasRoleOrClaimMappingExtensionPoint { get; set; }

        public bool HasProtectedEndpoint { get; set; }

        public bool HasUseAuthorization { get; set; }

        public string? FirstEvidencePath { get; set; }
    }
}

public sealed record AuthorizationFoundationResult(
    bool HasFoundation,
    bool HasPackageAuthorizationSetup,
    bool HasPackagePolicySetup,
    bool HasPackageRoleOrClaimMappingExtensionPoint,
    bool HasPackageProtectedEndpoint,
    bool HasSampleProtectedEndpoint,
    bool HasPackageUseAuthorization,
    string? EvidencePath);
