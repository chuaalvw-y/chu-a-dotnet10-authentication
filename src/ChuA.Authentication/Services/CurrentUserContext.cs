// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace ChuA.Authentication.Services;

public sealed class CurrentUserContext(
    IHttpContextAccessor httpContextAccessor,
    IOptions<ChuAAuthenticationOptions> options,
    IClaimsMappingService claimsMappingService,
    IRoleService roleService,
    IPermissionService permissionService) : ICurrentUserContext
{
    private ClaimsPrincipal User => httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());

    public string? UserId => FindFirstValue(options.Value.Claims.UserIdClaimTypes);
    public string? UserName => FindFirstValue(options.Value.Claims.UserNameClaimTypes);
    public string? Email => FindFirstValue(options.Value.Claims.EmailClaimTypes);
    public IReadOnlyCollection<string> Roles => claimsMappingService.GetRoles(User);
    public IReadOnlyCollection<string> Permissions => claimsMappingService.GetPermissions(User);
    public IReadOnlyCollection<string> Scopes => claimsMappingService.GetScopes(User);
    public IReadOnlyCollection<Claim> Claims => User.Claims.ToArray();
    public bool IsAuthenticated => User.Identity?.IsAuthenticated == true;

    public bool HasRole(string role) => roleService.HasRole(User, role);
    public bool HasPermission(string permission) => permissionService.HasPermission(User, permission);
    public bool HasScope(string scope) => permissionService.HasScope(User, scope);

    public CurrentUser ToCurrentUser()
        => new(UserId, UserName, Email, Roles, Permissions, Scopes, Claims, IsAuthenticated);

    private string? FindFirstValue(IEnumerable<string> claimTypes)
        => claimTypes.Select(User.FindFirstValue).FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));
}
