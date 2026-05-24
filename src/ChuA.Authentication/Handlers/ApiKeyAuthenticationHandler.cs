// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace ChuA.Authentication.Handlers;

public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<ChuAAuthenticationOptions> chuAOptions,
    IApiKeyValidator apiKeyValidator)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var providerOptions = chuAOptions.Value.GetDefaultProviderOptions();
        var headerName = string.IsNullOrWhiteSpace(providerOptions.HeaderName)
            ? ChuAAuthenticationDefaults.DefaultApiKeyHeaderName
            : providerOptions.HeaderName;

        if (!Request.Headers.TryGetValue(headerName, out var headerValues))
        {
            return AuthenticateResult.NoResult();
        }

        var apiKey = headerValues.FirstOrDefault();
        if (!await apiKeyValidator.IsValidAsync(apiKey ?? string.Empty, Context.RequestAborted))
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "api-key-client"),
            new Claim(ClaimTypes.Name, "API Key Client")
        };
        var scheme = string.IsNullOrWhiteSpace(providerOptions.Scheme) ? ChuAAuthenticationDefaults.ApiKeyScheme : providerOptions.Scheme;
        var identity = new ClaimsIdentity(claims, scheme);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), scheme);

        return AuthenticateResult.Success(ticket);
    }
}
