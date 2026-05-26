// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;

namespace ChuA.Authentication.Providers;

internal static class Auth0AuthorityNormalizer
{
    public static void ApplyDomainAuthorityFallback(ChuAProviderOptions provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        if (IsAuth0Provider(provider.Type)
            && string.IsNullOrWhiteSpace(provider.Authority)
            && !string.IsNullOrWhiteSpace(provider.Domain))
        {
            provider.Authority = $"https://{provider.Domain.TrimEnd('/')}/";
        }
    }

    private static bool IsAuth0Provider(string? providerType)
        => string.Equals(providerType, ChuAAuthenticationDefaults.Auth0Provider, StringComparison.OrdinalIgnoreCase)
            || string.Equals(providerType, ChuAAuthenticationDefaults.Auth0WebAppProvider, StringComparison.OrdinalIgnoreCase);
}
