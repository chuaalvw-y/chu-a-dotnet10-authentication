// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Constants;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace ChuA.Authentication.Configuration;

public sealed class ChuAAuthenticationOptions
{
    [Obsolete("Use ProviderName, DefaultProvider, and Providers instead. This property remains for backward compatibility.")]
    public AuthenticationProvider Provider { get; set; } = AuthenticationProvider.StandardJwt;
    public string? ProviderName { get; set; }
    public string? ProviderType { get; set; }
    public string? DefaultProvider { get; set; }
    public string? DefaultScheme { get; set; }
    public string? Authority { get; set; }
    public string? MetadataAddress { get; set; }
    public string? Domain { get; set; }
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? Audience { get; set; }
    public string? ValidIssuer { get; set; }
    public List<string> ValidIssuers { get; set; } = [];
    public string? ValidAudience { get; set; }
    public List<string> ValidAudiences { get; set; } = [];
    public bool RequireHttpsMetadata { get; set; } = true;
    public bool SaveToken { get; set; }
    public string RoleClaimType { get; set; } = ClaimTypes.Role;
    public string NameClaimType { get; set; } = ClaimTypes.Name;
    public string PermissionClaimType { get; set; } = ChuAAuthenticationDefaults.DefaultPermissionClaimType;
    public string ScopeClaimType { get; set; } = ChuAAuthenticationDefaults.DefaultScopeClaimType;
    public bool EnableClaimsTransformation { get; set; } = true;
    public List<string> RequiredPermissions { get; set; } = [];
    public List<string> RequiredRoles { get; set; } = [];
    public List<ChuAAuthorizationPolicyOptions> Policies { get; set; } = [];
    public string ApiKeyHeaderName { get; set; } = ChuAAuthenticationDefaults.DefaultApiKeyHeaderName;
    public string? ApiKey { get; set; }
    public bool RequireAuthenticatedUserByDefault { get; set; } = true;
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);
    public bool ValidateIssuer { get; set; } = true;
    public bool ValidateAudience { get; set; } = true;
    public bool ValidateIssuerSigningKey { get; set; } = true;
    public bool ValidateLifetime { get; set; } = true;
    public bool RequireExpirationTime { get; set; } = true;
    public bool RequireSignedTokens { get; set; } = true;
    public ChuAClaimsOptions Claims { get; set; } = new();
    public Dictionary<string, ChuAProviderOptions> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    [Obsolete("Use provider-specific configurators or the neutral Authority setting instead.")]
    public string? GetResolvedAuthority()
    {
        return string.IsNullOrWhiteSpace(Authority) ? null : Authority.TrimEnd('/');
    }

    public IEnumerable<string> GetAudiences()
    {
        if (!string.IsNullOrWhiteSpace(Audience))
        {
            yield return Audience;
        }

        if (!string.IsNullOrWhiteSpace(ValidAudience))
        {
            yield return ValidAudience;
        }

        foreach (var audience in ValidAudiences.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return audience;
        }
    }

    public IEnumerable<string> GetIssuers()
    {
        if (!string.IsNullOrWhiteSpace(ValidIssuer))
        {
            yield return ValidIssuer;
        }

        foreach (var issuer in ValidIssuers.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return issuer;
        }
    }

    public ChuAProviderOptions GetDefaultProviderOptions()
    {
        var providerName = DefaultProvider ?? ProviderName;
        if (!string.IsNullOrWhiteSpace(providerName) && Providers.TryGetValue(providerName, out var namedProvider))
        {
            ApplyRootFallbacks(namedProvider);
            return namedProvider;
        }

        var compatibilityProvider = new ChuAProviderOptions
        {
            Type = ProviderType ?? ProviderName ?? GetLegacyProviderTypeName(),
            Scheme = DefaultScheme,
            Authority = Authority,
            MetadataAddress = MetadataAddress,
            Domain = Domain,
            TenantId = TenantId,
            ClientId = ClientId,
            Audience = Audience,
            ValidIssuer = ValidIssuer,
            ValidIssuers = [.. ValidIssuers],
            ValidAudience = ValidAudience,
            ValidAudiences = [.. ValidAudiences],
            RequireHttpsMetadata = RequireHttpsMetadata,
            SaveToken = SaveToken,
            HeaderName = ApiKeyHeaderName,
            ApiKey = ApiKey
        };

        ApplyRootFallbacks(compatibilityProvider);
        return compatibilityProvider;
    }

    public TokenValidationParameters BuildTokenValidationParameters()
        => BuildTokenValidationParameters(GetDefaultProviderOptions());

    public TokenValidationParameters BuildTokenValidationParameters(ChuAProviderOptions provider)
    {
        var audiences = GetProviderAudiences(provider).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var issuers = GetProviderIssuers(provider).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        return new TokenValidationParameters
        {
            ValidateIssuer = ValidateIssuer,
            ValidIssuer = provider.ValidIssuer ?? ValidIssuer,
            ValidIssuers = issuers,
            ValidateAudience = ValidateAudience,
            ValidAudience = provider.ValidAudience ?? provider.Audience ?? ValidAudience ?? Audience,
            ValidAudiences = audiences,
            ValidateIssuerSigningKey = ValidateIssuerSigningKey,
            ValidateLifetime = ValidateLifetime,
            RequireExpirationTime = RequireExpirationTime,
            RequireSignedTokens = RequireSignedTokens,
            ClockSkew = ClockSkew,
            RoleClaimType = RoleClaimType,
            NameClaimType = NameClaimType
        };
    }

    private void ApplyRootFallbacks(ChuAProviderOptions provider)
    {
        provider.Scheme ??= DefaultScheme;
        provider.Authority ??= Authority;
        provider.MetadataAddress ??= MetadataAddress;
        provider.Audience ??= Audience;
        provider.ValidIssuer ??= ValidIssuer;
        provider.ValidAudience ??= ValidAudience;
        provider.Domain ??= Domain;
        provider.TenantId ??= TenantId;
        provider.ClientId ??= ClientId;
        provider.HeaderName ??= ApiKeyHeaderName;
        provider.ApiKey ??= ApiKey;
        provider.SaveToken = provider.SaveToken || SaveToken;

        if (provider.ValidIssuers.Count == 0)
        {
            provider.ValidIssuers = [.. ValidIssuers];
        }

        if (provider.ValidAudiences.Count == 0)
        {
            provider.ValidAudiences = [.. ValidAudiences];
        }
    }

    private IEnumerable<string> GetProviderAudiences(ChuAProviderOptions provider)
    {
        if (!string.IsNullOrWhiteSpace(provider.Audience))
        {
            yield return provider.Audience;
        }

        if (!string.IsNullOrWhiteSpace(provider.ValidAudience))
        {
            yield return provider.ValidAudience;
        }

        foreach (var audience in provider.ValidAudiences.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return audience;
        }
    }

    private IEnumerable<string> GetProviderIssuers(ChuAProviderOptions provider)
    {
        if (!string.IsNullOrWhiteSpace(provider.ValidIssuer))
        {
            yield return provider.ValidIssuer;
        }

        foreach (var issuer in provider.ValidIssuers.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return issuer;
        }
    }

    private string GetLegacyProviderTypeName()
    {
#pragma warning disable CS0618
        return Provider.ToProviderTypeName();
#pragma warning restore CS0618
    }
}

internal static class AuthenticationProviderCompatibilityExtensions
{
    public static string ToProviderTypeName(this AuthenticationProvider provider)
        => provider switch
        {
            AuthenticationProvider.StandardJwt => ChuAAuthenticationDefaults.GenericJwtProvider,
            AuthenticationProvider.Auth0 => ChuAAuthenticationDefaults.Auth0Provider,
            AuthenticationProvider.EntraId => ChuAAuthenticationDefaults.EntraIdProvider,
            AuthenticationProvider.ActiveDirectory => ChuAAuthenticationDefaults.ActiveDirectoryProvider,
            AuthenticationProvider.CloudProvider => ChuAAuthenticationDefaults.CloudProvider,
            AuthenticationProvider.ApiKey => ChuAAuthenticationDefaults.ApiKeyProvider,
            _ => ChuAAuthenticationDefaults.GenericJwtProvider
        };
}
