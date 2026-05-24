// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace ChuA.Authentication.Providers;

public sealed class JwtAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => ChuAAuthenticationDefaults.GenericJwtProvider;

    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
        => ConfigureJwtBearer(builder, options, provider);

    internal static void ConfigureJwtBearer(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        ValidateJwtProvider(provider, options);

        var scheme = string.IsNullOrWhiteSpace(provider.Scheme) ? JwtBearerDefaults.AuthenticationScheme : provider.Scheme;
        builder.AddJwtBearer(scheme, jwtOptions =>
        {
            jwtOptions.Authority = NormalizeAuthority(provider.Authority);
            if (!string.IsNullOrWhiteSpace(provider.MetadataAddress))
            {
                jwtOptions.MetadataAddress = provider.MetadataAddress;
            }
            jwtOptions.Audience = provider.Audience;
            jwtOptions.RequireHttpsMetadata = provider.RequireHttpsMetadata;
            jwtOptions.SaveToken = provider.SaveToken;
            jwtOptions.MapInboundClaims = false;
            jwtOptions.TokenValidationParameters = options.BuildTokenValidationParameters(provider);
        });
    }

    internal static string? NormalizeAuthority(string? authority)
        => string.IsNullOrWhiteSpace(authority) ? null : authority.TrimEnd('/');

    internal static void ValidateJwtProvider(ChuAProviderOptions provider, ChuAAuthenticationOptions options)
    {
        if (options.ValidateIssuer && string.IsNullOrWhiteSpace(provider.ValidIssuer) && provider.ValidIssuers.Count == 0 && string.IsNullOrWhiteSpace(provider.Authority))
        {
            throw new InvalidOperationException($"Provider '{provider.Type}' requires Authority, ValidIssuer, or ValidIssuers when issuer validation is enabled.");
        }

        if (options.ValidateAudience && string.IsNullOrWhiteSpace(provider.Audience) && string.IsNullOrWhiteSpace(provider.ValidAudience) && provider.ValidAudiences.Count == 0)
        {
            throw new InvalidOperationException($"Provider '{provider.Type}' requires Audience, ValidAudience, or ValidAudiences when audience validation is enabled.");
        }
    }
}
