// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

namespace ChuA.Authentication.Constants;

/// <summary>
/// Shared constants used by ChuA authentication configuration.
/// </summary>
public static class ChuAAuthenticationDefaults
{
    public const string ConfigurationSectionName = "ChuAAuthentication";
    public const string ApiKeyScheme = "ChuAApiKey";
    public const string BearerScheme = "Bearer";
    public const string GenericJwtProvider = "GenericJwt";
    public const string GenericOidcProvider = "GenericOidc";
    public const string Auth0Provider = "Auth0";
    public const string EntraIdProvider = "EntraId";
    public const string ActiveDirectoryProvider = "ActiveDirectory";
    public const string CloudProvider = "CloudProvider";
    public const string ApiKeyProvider = "ApiKey";
    public const string DefaultApiKeyHeaderName = "X-API-Key";
    public const string DefaultPermissionClaimType = "permissions";
    public const string DefaultScopeClaimType = "scope";
}
