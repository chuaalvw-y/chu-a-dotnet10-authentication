// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using System.Security.Claims;

namespace ChuA.Authentication.Services;

public sealed class RoleService(IClaimsMappingService claimsMappingService) : IRoleService
{
    public bool HasRole(ClaimsPrincipal principal, string role)
        => !string.IsNullOrWhiteSpace(role)
           && claimsMappingService.GetRoles(principal).Contains(role, StringComparer.OrdinalIgnoreCase);
}
