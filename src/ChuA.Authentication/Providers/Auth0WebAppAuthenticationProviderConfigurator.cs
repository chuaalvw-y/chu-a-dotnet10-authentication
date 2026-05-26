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
/// Configures an interactive cookie + OIDC code-flow web application backed by Auth0.
/// Mirrors the JWT-bearer <see cref="Auth0AuthenticationProviderConfigurator"/>: normalizes
/// the Auth0 <see cref="ChuAProviderOptions.Domain"/> into the standard OIDC
/// <see cref="ChuAProviderOptions.Authority"/> (<c>https://{domain}/</c>) and then delegates
/// to <see cref="OidcWebAppAuthenticationProviderConfigurator.ConfigureOidcWebApp"/>.
///
/// Federated logout uses the OIDC <c>end_session_endpoint</c> exposed by Auth0's discovery
/// document (<c>https://{domain}/oidc/logout</c>), so no Auth0-specific event handlers are
/// required for the standard flow.
/// </summary>
public sealed class Auth0WebAppAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    /// <inheritdoc />
    public string ProviderType => ChuAAuthenticationDefaults.Auth0WebAppProvider;

    /// <inheritdoc />
    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        Auth0AuthorityNormalizer.ApplyDomainAuthorityFallback(provider);
        OidcWebAppAuthenticationProviderConfigurator.ConfigureOidcWebApp(builder, options, provider);
    }
}
