// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using ChuA.Authentication.Handlers;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Providers;

public sealed class ApiKeyAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => ChuAAuthenticationDefaults.ApiKeyProvider;

    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        var scheme = string.IsNullOrWhiteSpace(provider.Scheme) ? ChuAAuthenticationDefaults.ApiKeyScheme : provider.Scheme;
        builder.AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
            scheme,
            configureOptions: null);
    }
}
