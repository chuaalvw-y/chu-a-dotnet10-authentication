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
}
