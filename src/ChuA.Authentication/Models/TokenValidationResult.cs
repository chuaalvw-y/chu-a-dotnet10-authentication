// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using System.Security.Claims;

namespace ChuA.Authentication.Models;

public sealed record TokenValidationResult
{
    public bool IsValid { get; init; }
    public ClaimsPrincipal? Principal { get; init; }
    public string? Error { get; init; }

    public static TokenValidationResult Success(ClaimsPrincipal principal) => new() { IsValid = true, Principal = principal };
    public static TokenValidationResult Failure(string error) => new() { IsValid = false, Error = error };
}
