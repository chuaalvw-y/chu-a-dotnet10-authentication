// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Authorization;
using ChuA.Authentication.Configuration;
using Microsoft.AspNetCore.Authorization;

namespace ChuA.Authentication.Services;

public sealed class AuthorizationPolicyProviderService : IAuthorizationPolicyProviderService
{
    public AuthorizationPolicy BuildPolicy(ChuAAuthorizationPolicyOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Name);

        var builder = new AuthorizationPolicyBuilder();

        if (options.RequireAuthenticatedUser)
        {
            builder.RequireAuthenticatedUser();
        }

        foreach (var role in options.RequiredRoles.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            builder.RequireRole(role);
        }

        foreach (var permission in options.RequiredPermissions.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            builder.AddRequirements(new PermissionRequirement(permission));
        }

        foreach (var scope in options.RequiredScopes.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            builder.AddRequirements(new ScopeRequirement(scope));
        }

        return builder.Build();
    }
}
