// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace ChuA.Authentication.Claims;

public sealed class ChuAClaimsTransformation(
    IClaimsMappingService claimsMappingService,
    IEnumerable<IClaimsEnricher> claimsEnrichers,
    IHttpContextAccessor httpContextAccessor) : IClaimsTransformation
{
    private const string ClaimsTransformationPrincipalItemKey =
        "__ChuAAuthentication_ClaimsTransformation_Principal";

    private const string ClaimsTransformationInProgressItemKey =
        "__ChuAAuthentication_ClaimsTransformation_InProgress";

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext?.Items[ClaimsTransformationInProgressItemKey] is true
            && httpContext.Items[ClaimsTransformationPrincipalItemKey] is ClaimsPrincipal inProgressPrincipal)
        {
            return inProgressPrincipal;
        }

        var currentPrincipal = claimsMappingService.MapClaims(principal);
        if (httpContext is null)
        {
            foreach (var enricher in claimsEnrichers)
            {
                currentPrincipal = await enricher.EnrichAsync(currentPrincipal);
            }

            return currentPrincipal;
        }

        httpContext.Items[ClaimsTransformationPrincipalItemKey] = currentPrincipal;
        httpContext.Items[ClaimsTransformationInProgressItemKey] = true;

        try
        {
            foreach (var enricher in claimsEnrichers)
            {
                currentPrincipal = await enricher.EnrichAsync(currentPrincipal);
            }

            httpContext.Items[ClaimsTransformationPrincipalItemKey] = currentPrincipal;
            return currentPrincipal;
        }
        finally
        {
            httpContext.Items[ClaimsTransformationInProgressItemKey] = false;
        }
    }
}
