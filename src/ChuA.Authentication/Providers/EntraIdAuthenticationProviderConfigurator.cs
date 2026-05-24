// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Providers;

public sealed class EntraIdAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => ChuAAuthenticationDefaults.EntraIdProvider;

    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        if (string.IsNullOrWhiteSpace(provider.Authority) && !string.IsNullOrWhiteSpace(provider.TenantId))
        {
            provider.Authority = $"https://login.microsoftonline.com/{provider.TenantId.Trim('/')}/v2.0";
        }

        JwtAuthenticationProviderConfigurator.ConfigureJwtBearer(builder, options, provider);
    }
}
