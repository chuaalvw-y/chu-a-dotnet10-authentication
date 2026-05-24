// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using System.Security.Claims;

namespace ChuA.Authentication.Abstractions;

public interface IPermissionService
{
    bool HasPermission(ClaimsPrincipal principal, string permission);
    bool HasScope(ClaimsPrincipal principal, string scope);
}
