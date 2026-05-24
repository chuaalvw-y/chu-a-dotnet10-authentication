// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Providers;

/// <summary>
/// Configures a generic OIDC-compatible JWT bearer provider.
/// </summary>
public sealed class GenericOidcAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => ChuAAuthenticationDefaults.GenericOidcProvider;

    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
        => JwtAuthenticationProviderConfigurator.ConfigureJwtBearer(builder, options, provider);
}
