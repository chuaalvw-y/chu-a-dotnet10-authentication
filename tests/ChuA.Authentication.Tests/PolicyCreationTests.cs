// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Authorization;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Services;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace ChuA.Authentication.Tests;

public sealed class PolicyCreationTests
{
    [Fact]
    public void BuildsPolicyWithRolesPermissionsAndScopes()
    {
        var service = new AuthorizationPolicyProviderService();

        var policy = service.BuildPolicy(new ChuAAuthorizationPolicyOptions
        {
            Name = "CanAdministerAccount",
            RequiredRoles = ["AccountAdmin"],
            RequiredPermissions = ["account:create"],
            RequiredScopes = ["account:read"]
        });

        Assert.Contains(policy.Requirements, requirement => requirement is DenyAnonymousAuthorizationRequirement);
        Assert.Contains(policy.Requirements, requirement => requirement is RolesAuthorizationRequirement roles
            && roles.AllowedRoles.Contains("AccountAdmin"));
        Assert.Contains(policy.Requirements, requirement => requirement is PermissionRequirement permission
            && permission.Permission == "account:create");
        Assert.Contains(policy.Requirements, requirement => requirement is ScopeRequirement scope
            && scope.Scope == "account:read");
    }
}
