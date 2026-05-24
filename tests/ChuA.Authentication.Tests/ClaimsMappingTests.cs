// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using ChuA.Authentication.Services;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace ChuA.Authentication.Tests;

public sealed class ClaimsMappingTests
{
    [Fact]
    public void MapsAuth0RolesPermissionsAndScopes()
    {
        var service = CreateService(new ChuAAuthenticationOptions
        {
            RoleClaimType = "roles",
            PermissionClaimType = "permissions",
            ScopeClaimType = "scope"
        });
        var principal = CreatePrincipal(
            new Claim("roles", "[\"AccountAdmin\",\"Auditor\"]"),
            new Claim("permissions", "account:create account:read"),
            new Claim("scope", "openid profile account:read"));

        Assert.Contains("AccountAdmin", service.GetRoles(principal));
        Assert.Contains("account:create", service.GetPermissions(principal));
        Assert.Contains("account:read", service.GetScopes(principal));
    }

    [Fact]
    public void ReadsEntraIdScopeConvention()
    {
        var service = CreateService(new ChuAAuthenticationOptions());
        var principal = CreatePrincipal(new Claim("scp", "Files.Read User.Read"));

        Assert.Contains("Files.Read", service.GetScopes(principal));
        Assert.Contains("User.Read", service.GetScopes(principal));
    }

    [Fact]
    public void UsesConfiguredProviderNeutralClaimTypes()
    {
        var service = CreateService(new ChuAAuthenticationOptions
        {
            Claims = new ChuAClaimsOptions
            {
                RoleClaimTypes = ["custom_roles"],
                PermissionClaimTypes = ["custom_permissions"],
                ScopeClaimTypes = ["custom_scopes"]
            }
        });
        var principal = CreatePrincipal(
            new Claim("custom_roles", "Approver"),
            new Claim("custom_permissions", "invoice:approve"),
            new Claim("custom_scopes", "invoice:read"));

        Assert.Contains("Approver", service.GetRoles(principal));
        Assert.Contains("invoice:approve", service.GetPermissions(principal));
        Assert.Contains("invoice:read", service.GetScopes(principal));
    }

    private static ClaimsMappingService CreateService(ChuAAuthenticationOptions options)
        => new(Options.Create(options));

    private static ClaimsPrincipal CreatePrincipal(params Claim[] claims)
        => new(new ClaimsIdentity(claims, "Bearer"));
}
