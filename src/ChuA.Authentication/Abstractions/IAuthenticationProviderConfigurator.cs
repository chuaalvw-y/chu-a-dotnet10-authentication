// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using Microsoft.AspNetCore.Authentication;

namespace ChuA.Authentication.Abstractions;

/// <summary>
/// Configures an authentication provider identified by a string provider type key.
/// </summary>
public interface IAuthenticationProviderConfigurator
{
    /// <summary>The provider type key handled by this configurator.</summary>
    string ProviderType { get; }

    /// <summary>Returns true when this configurator can configure the supplied provider.</summary>
    bool CanConfigure(ChuAProviderOptions provider)
        => string.Equals(ProviderType, provider.Type, StringComparison.OrdinalIgnoreCase);

    /// <summary>Registers the authentication scheme for the supplied provider.</summary>
    void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider);
}
