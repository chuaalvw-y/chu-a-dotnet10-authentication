// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Claims;

public sealed class ChuAClaimsTransformation(IClaimsMappingService claimsMappingService) : IClaimsTransformation
{
    public Task<System.Security.Claims.ClaimsPrincipal> TransformAsync(System.Security.Claims.ClaimsPrincipal principal)
        => Task.FromResult(claimsMappingService.MapClaims(principal));
}
