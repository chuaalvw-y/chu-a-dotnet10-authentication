// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using ChuA.Authentication.Services;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace ChuA.Authentication.Tests;

public sealed class PermissionAndRoleServiceTests
{
    [Fact]
    public void PermissionAndRoleChecksAreCaseInsensitive()
    {
        var mapping = new ClaimsMappingService(Options.Create(new ChuAAuthenticationOptions { RoleClaimType = "roles" }));
        var permissions = new PermissionService(mapping);
        var roles = new RoleService(mapping);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("roles", "AccountAdmin"),
            new Claim("permissions", "account:create"),
            new Claim("scope", "account:read")
        ], "Bearer"));

        Assert.True(roles.HasRole(principal, "accountadmin"));
        Assert.True(permissions.HasPermission(principal, "ACCOUNT:CREATE"));
        Assert.True(permissions.HasScope(principal, "ACCOUNT:READ"));
        Assert.False(permissions.HasPermission(principal, "account:delete"));
    }
}
