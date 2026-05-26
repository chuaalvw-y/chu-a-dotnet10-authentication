// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Constants;

namespace ChuA.Authentication.Configuration;

/// <summary>
/// Neutral provider configuration used by built-in and custom provider configurators.
/// </summary>
public sealed class ChuAProviderOptions
{
    /// <summary>The provider preset or custom provider type key.</summary>
    public string Type { get; set; } = ChuAAuthenticationDefaults.GenericJwtProvider;

    /// <summary>The authentication scheme to register.</summary>
    public string? Scheme { get; set; }

    /// <summary>OIDC/JWT authority.</summary>
    public string? Authority { get; set; }

    /// <summary>Explicit metadata address for OIDC discovery.</summary>
    public string? MetadataAddress { get; set; }

    /// <summary>Primary expected audience.</summary>
    public string? Audience { get; set; }

    /// <summary>Primary expected issuer.</summary>
    public string? ValidIssuer { get; set; }

    /// <summary>Additional accepted issuers.</summary>
    public List<string> ValidIssuers { get; set; } = [];

    /// <summary>Primary expected audience.</summary>
    public string? ValidAudience { get; set; }

    /// <summary>Additional accepted audiences.</summary>
    public List<string> ValidAudiences { get; set; } = [];

    /// <summary>Requires HTTPS for metadata discovery.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Saves the bearer token in authentication properties.</summary>
    public bool SaveToken { get; set; }

    /// <summary>Auth0 convenience domain setting.</summary>
    public string? Domain { get; set; }

    /// <summary>Microsoft tenant convenience setting.</summary>
    public string? TenantId { get; set; }

    /// <summary>Optional client identifier for providers that need it.</summary>
    public string? ClientId { get; set; }

    /// <summary>API key header name for API key providers.</summary>
    public string? HeaderName { get; set; }

    /// <summary>Configured API key for simple internal service-to-service validation.</summary>
    public string? ApiKey { get; set; }

    // --- OIDC interactive web-app fields (cookie + AddOpenIdConnect code flow) ---
    // These are consumed by the OidcWebApp / Auth0WebApp / etc. configurators.
    // JWT-bearer configurators ignore them.

    /// <summary>OIDC client secret for confidential web-app flows.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>OIDC callback path (e.g. "/signin-oidc"). Defaults to the AddOpenIdConnect default when null.</summary>
    public string? CallbackPath { get; set; }

    /// <summary>OIDC signed-out callback path (e.g. "/signout-callback-oidc"). Defaults to the AddOpenIdConnect default when null.</summary>
    public string? SignedOutCallbackPath { get; set; }

    /// <summary>OIDC scopes to request. When empty the configurator falls back to provider-appropriate defaults (typically openid, profile, email).</summary>
    public List<string> Scopes { get; set; } = [];

    /// <summary>Cookie authentication scheme to register alongside the OIDC handler. Defaults to <c>CookieAuthenticationDefaults.AuthenticationScheme</c> ("Cookies") when null.</summary>
    public string? CookieScheme { get; set; }

    /// <summary>Whether the OIDC handler should use PKCE. Recommended on.</summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>Whether the OIDC handler should save tokens (id_token, access_token, refresh_token) in the authentication ticket.</summary>
    public bool SaveTokens { get; set; } = true;

    /// <summary>OIDC response type. Defaults to <c>"code"</c> when null.</summary>
    public string? ResponseType { get; set; }

    /// <summary>Whether the OIDC handler should call the UserInfo endpoint after token exchange.</summary>
    public bool GetClaimsFromUserInfoEndpoint { get; set; } = true;

    /// <summary>Per-provider override for the role claim type used by the OIDC handler's TokenValidationParameters. Falls back to the root <c>RoleClaimType</c> when null.</summary>
    public string? RoleClaimType { get; set; }

    /// <summary>Per-provider override for the name claim type used by the OIDC handler's TokenValidationParameters. Falls back to the root <c>NameClaimType</c> when null.</summary>
    public string? NameClaimType { get; set; }
}
