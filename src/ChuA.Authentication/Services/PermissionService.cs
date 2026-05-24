// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using System.Security.Claims;

namespace ChuA.Authentication.Services;

public sealed class PermissionService(IClaimsMappingService claimsMappingService) : IPermissionService
{
    public bool HasPermission(ClaimsPrincipal principal, string permission)
        => !string.IsNullOrWhiteSpace(permission)
           && claimsMappingService.GetPermissions(principal).Contains(permission, StringComparer.OrdinalIgnoreCase);

    public bool HasScope(ClaimsPrincipal principal, string scope)
        => !string.IsNullOrWhiteSpace(scope)
           && claimsMappingService.GetScopes(principal).Contains(scope, StringComparer.OrdinalIgnoreCase);
}
