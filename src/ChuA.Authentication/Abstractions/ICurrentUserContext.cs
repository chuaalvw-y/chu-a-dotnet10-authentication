// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Models;
using System.Security.Claims;

namespace ChuA.Authentication.Abstractions;

public interface ICurrentUserContext
{
    string? UserId { get; }
    string? UserName { get; }
    string? Email { get; }
    IReadOnlyCollection<string> Roles { get; }
    IReadOnlyCollection<string> Permissions { get; }
    IReadOnlyCollection<string> Scopes { get; }
    IReadOnlyCollection<Claim> Claims { get; }
    bool IsAuthenticated { get; }
    bool HasRole(string role);
    bool HasPermission(string permission);
    bool HasScope(string scope);
    CurrentUser ToCurrentUser();
}
