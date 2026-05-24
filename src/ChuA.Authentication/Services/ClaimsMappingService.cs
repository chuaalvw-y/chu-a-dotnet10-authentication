// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Utilities;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace ChuA.Authentication.Services;

public sealed class ClaimsMappingService(IOptions<ChuAAuthenticationOptions> options) : IClaimsMappingService
{
    private readonly ChuAAuthenticationOptions _options = options.Value;

    public ClaimsPrincipal MapClaims(ClaimsPrincipal principal)
    {
        if (!_options.EnableClaimsTransformation || principal.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
        {
            return principal;
        }

        AddMissingClaims(identity, ClaimTypes.Role, GetRoles(principal));
        AddMissingClaims(identity, _options.PermissionClaimType, GetPermissions(principal));
        AddMissingClaims(identity, _options.ScopeClaimType, GetScopes(principal));

        return principal;
    }

    public IReadOnlyCollection<string> GetRoles(ClaimsPrincipal principal)
        => ClaimValueReader.ReadValues(principal, GetClaimTypes(_options.Claims.RoleClaimTypes, _options.RoleClaimType).ToArray());

    public IReadOnlyCollection<string> GetPermissions(ClaimsPrincipal principal)
        => ClaimValueReader.ReadValues(principal, GetClaimTypes(_options.Claims.PermissionClaimTypes, _options.PermissionClaimType).ToArray());

    public IReadOnlyCollection<string> GetScopes(ClaimsPrincipal principal)
        => ClaimValueReader.ReadValues(principal, GetClaimTypes(_options.Claims.ScopeClaimTypes, _options.ScopeClaimType).ToArray());

    private static IEnumerable<string> GetClaimTypes(IEnumerable<string> configuredClaimTypes, string legacyClaimType)
    {
        if (!string.IsNullOrWhiteSpace(legacyClaimType))
        {
            yield return legacyClaimType;
        }

        foreach (var claimType in configuredClaimTypes.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return claimType;
        }
    }

    private static void AddMissingClaims(ClaimsIdentity identity, string claimType, IEnumerable<string> values)
    {
        var existingValues = identity.FindAll(claimType).Select(static claim => claim.Value).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var value in values.Where(value => !existingValues.Contains(value)))
        {
            identity.AddClaim(new Claim(claimType, value));
        }
    }
}
