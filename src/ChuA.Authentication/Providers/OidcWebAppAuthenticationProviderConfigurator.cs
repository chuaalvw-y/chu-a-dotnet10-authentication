// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ChuA.Authentication.Providers;

/// <summary>
/// Configures an interactive cookie + OpenID Connect code-flow web application for any
/// OIDC-compliant identity provider. Registers a cookie scheme (default <c>Cookies</c>) for
/// the authenticated session and an OIDC scheme (default <c>OpenIdConnect</c>) for the
/// browser challenge, then pins <see cref="AuthenticationOptions"/> defaults so cookies own
/// authenticate/sign-in and OIDC owns challenge/sign-out.
///
/// When <see cref="ChuAProviderOptions.ClientId"/> is empty, only the cookie scheme is
/// registered. That keeps a development "local sign-in" path (e.g. a DevLogin endpoint that
/// writes a cookie directly) working without a real IdP.
/// </summary>
public sealed class OidcWebAppAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    /// <inheritdoc />
    public string ProviderType => ChuAAuthenticationDefaults.OidcWebAppProvider;

    /// <inheritdoc />
    public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
        => ConfigureOidcWebApp(builder, options, provider);

    /// <summary>
    /// Registers the cookie + OIDC schemes for the supplied provider. Exposed so provider-specific
    /// configurators (e.g. <see cref="Auth0WebAppAuthenticationProviderConfigurator"/>) can normalize
    /// their inputs and then delegate the common wiring here.
    /// </summary>
    internal static void ConfigureOidcWebApp(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(provider);

        var cookieScheme = string.IsNullOrWhiteSpace(provider.CookieScheme)
            ? CookieAuthenticationDefaults.AuthenticationScheme
            : provider.CookieScheme;

        var oidcScheme = string.IsNullOrWhiteSpace(provider.Scheme)
            ? OpenIdConnectDefaults.AuthenticationScheme
            : provider.Scheme;

        // Cookie scheme is always present: the OIDC handler signs the user into it, and a
        // host's local DevLogin can also write directly to it when the IdP is not configured.
        builder.AddCookie(cookieScheme);

        var hasOidcCredentials =
            !string.IsNullOrWhiteSpace(provider.ClientId)
            && (!string.IsNullOrWhiteSpace(provider.Authority)
                || !string.IsNullOrWhiteSpace(provider.MetadataAddress)
                || !string.IsNullOrWhiteSpace(provider.Domain));

        if (!hasOidcCredentials)
        {
            // Dev / local sign-in mode: cookie-only. Pin every default to the cookie so that
            // [Authorize] redirects to the cookie's LoginPath (host responsibility) instead of
            // attempting an unconfigured OIDC challenge.
            builder.Services.PostConfigure<AuthenticationOptions>(authOptions =>
            {
                authOptions.DefaultScheme = cookieScheme;
                authOptions.DefaultAuthenticateScheme = cookieScheme;
                authOptions.DefaultChallengeScheme = cookieScheme;
                authOptions.DefaultSignInScheme = cookieScheme;
                authOptions.DefaultSignOutScheme = cookieScheme;
            });
            return;
        }

        var authority = NormalizeAuthority(provider.Authority);

        builder.AddOpenIdConnect(oidcScheme, oidcOptions =>
        {
            oidcOptions.SignInScheme = cookieScheme;
            oidcOptions.SignOutScheme = cookieScheme;
            oidcOptions.Authority = authority;
            if (!string.IsNullOrWhiteSpace(provider.MetadataAddress))
            {
                oidcOptions.MetadataAddress = provider.MetadataAddress;
            }
            oidcOptions.ClientId = provider.ClientId;
            oidcOptions.ClientSecret = provider.ClientSecret;
            if (!string.IsNullOrWhiteSpace(provider.CallbackPath))
            {
                oidcOptions.CallbackPath = provider.CallbackPath;
            }
            if (!string.IsNullOrWhiteSpace(provider.SignedOutCallbackPath))
            {
                oidcOptions.SignedOutCallbackPath = provider.SignedOutCallbackPath;
            }
            oidcOptions.ResponseType = string.IsNullOrWhiteSpace(provider.ResponseType)
                ? OpenIdConnectResponseType.Code
                : provider.ResponseType;
            oidcOptions.UsePkce = provider.UsePkce;
            oidcOptions.SaveTokens = provider.SaveTokens;
            oidcOptions.GetClaimsFromUserInfoEndpoint = provider.GetClaimsFromUserInfoEndpoint;
            oidcOptions.RequireHttpsMetadata = provider.RequireHttpsMetadata;
            oidcOptions.MapInboundClaims = false;

            oidcOptions.Scope.Clear();
            var scopes = provider.Scopes.Count > 0
                ? (IEnumerable<string>)provider.Scopes
                : DefaultScopes;
            foreach (var scope in scopes)
            {
                if (!string.IsNullOrWhiteSpace(scope))
                {
                    oidcOptions.Scope.Add(scope);
                }
            }

            oidcOptions.TokenValidationParameters.NameClaimType = provider.NameClaimType ?? options.NameClaimType;
            oidcOptions.TokenValidationParameters.RoleClaimType = provider.RoleClaimType ?? options.RoleClaimType;

            if (!string.IsNullOrWhiteSpace(provider.Audience))
            {
                // In OIDC code flow, ClientId validates the ID token audience. Audience is
                // sent as an authorization parameter to request an API access token; do not
                // assign it to TokenValidationParameters.ValidAudience.
                oidcOptions.AdditionalAuthorizationParameters["audience"] = provider.Audience;
            }
        });

        // Pin the scheme defaults: cookie owns who-am-I + sign-in; OIDC owns challenge + sign-out.
        builder.Services.PostConfigure<AuthenticationOptions>(authOptions =>
        {
            authOptions.DefaultScheme = cookieScheme;
            authOptions.DefaultAuthenticateScheme = cookieScheme;
            authOptions.DefaultSignInScheme = cookieScheme;
            authOptions.DefaultChallengeScheme = oidcScheme;
            authOptions.DefaultSignOutScheme = oidcScheme;
        });
    }

    private static readonly string[] DefaultScopes = ["openid", "profile", "email"];

    private static string? NormalizeAuthority(string? authority)
        => string.IsNullOrWhiteSpace(authority) ? null : authority.TrimEnd('/');
}
