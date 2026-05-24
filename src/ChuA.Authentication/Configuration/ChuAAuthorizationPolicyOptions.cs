// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

namespace ChuA.Authentication.Configuration;

public sealed class ChuAAuthorizationPolicyOptions
{
    public string Name { get; set; } = string.Empty;
    public List<string> RequiredPermissions { get; set; } = [];
    public List<string> RequiredRoles { get; set; } = [];
    public List<string> RequiredScopes { get; set; } = [];
    public bool RequireAuthenticatedUser { get; set; } = true;
}
