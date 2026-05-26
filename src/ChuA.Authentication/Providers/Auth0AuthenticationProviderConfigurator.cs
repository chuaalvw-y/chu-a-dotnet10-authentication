// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Providers;

public sealed class Auth0AuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => ChuAAuthenticationDefaults.Auth0Provider;

    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        Auth0AuthorityNormalizer.ApplyDomainAuthorityFallback(provider);
        JwtAuthenticationProviderConfigurator.ConfigureJwtBearer(builder, options, provider);
    }
}
