// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using System.Security.Claims;

namespace ChuA.Authentication.Configuration;

/// <summary>
/// Configures provider-neutral claim type discovery.
/// </summary>
public sealed class ChuAClaimsOptions
{
    /// <summary>Claim types that can contain a stable user identifier.</summary>
    public List<string> UserIdClaimTypes { get; set; } = [ClaimTypes.NameIdentifier, "sub", "oid", "nameidentifier"];

    /// <summary>Claim types that can contain a display or login name.</summary>
    public List<string> UserNameClaimTypes { get; set; } = [ClaimTypes.Name, "name", "preferred_username", "email", "upn"];

    /// <summary>Claim types that can contain an email address.</summary>
    public List<string> EmailClaimTypes { get; set; } = [ClaimTypes.Email, "email", "upn", "preferred_username"];

    /// <summary>Claim types that can contain roles or group-like authorization values.</summary>
    public List<string> RoleClaimTypes { get; set; } = [ClaimTypes.Role, "roles", "role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "groups"];

    /// <summary>Claim types that can contain permissions.</summary>
    public List<string> PermissionClaimTypes { get; set; } = ["permissions", "permission"];

    /// <summary>Claim types that can contain OAuth scopes.</summary>
    public List<string> ScopeClaimTypes { get; set; } = ["scope", "scp"];
}
