// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

namespace ChuA.Authentication.Services;

public sealed class TokenValidationService(
    IOptions<ChuAAuthenticationOptions> options,
    ILogger<TokenValidationService> logger) : ITokenValidationService
{
    private readonly JwtSecurityTokenHandler _handler = new();

    public Task<TokenValidationResult> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult(TokenValidationResult.Failure("Token is required."));
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var principal = _handler.ValidateToken(token, options.Value.BuildTokenValidationParameters(), out _);
            return Task.FromResult(TokenValidationResult.Success(principal));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogDebug(exception, "Token validation failed.");
            return Task.FromResult(TokenValidationResult.Failure("Token validation failed."));
        }
    }
}
