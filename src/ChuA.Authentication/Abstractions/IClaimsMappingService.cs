// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using System.Security.Claims;

namespace ChuA.Authentication.Abstractions;

public interface IClaimsMappingService
{
    ClaimsPrincipal MapClaims(ClaimsPrincipal principal);
    IReadOnlyCollection<string> GetRoles(ClaimsPrincipal principal);
    IReadOnlyCollection<string> GetPermissions(ClaimsPrincipal principal);
    IReadOnlyCollection<string> GetScopes(ClaimsPrincipal principal);
}
