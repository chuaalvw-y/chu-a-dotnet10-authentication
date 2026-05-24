// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using Microsoft.Extensions.Configuration;

namespace ChuA.Authentication.Tests;

public sealed class OptionsBindingTests
{
    [Fact]
    public void BindsAuth0OptionsAndPoliciesFromConfiguration()
    {
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:Provider"] = "Auth0",
            ["ChuAAuthentication:Domain"] = "dev-example.us.auth0.com",
            ["ChuAAuthentication:Audience"] = "https://trust-account-api",
            ["ChuAAuthentication:RoleClaimType"] = "roles",
            ["ChuAAuthentication:PermissionClaimType"] = "permissions",
            ["ChuAAuthentication:ScopeClaimType"] = "scope",
            ["ChuAAuthentication:RequireHttpsMetadata"] = "true",
            ["ChuAAuthentication:Policies:0:Name"] = "CanCreateAccount",
            ["ChuAAuthentication:Policies:0:RequiredPermissions:0"] = "account:create",
            ["ChuAAuthentication:Policies:1:Name"] = "CanAdministerAccount",
            ["ChuAAuthentication:Policies:1:RequiredRoles:0"] = "AccountAdmin"
        });

        var options = configuration
            .GetSection(ChuAAuthenticationDefaults.ConfigurationSectionName)
            .Get<ChuAAuthenticationOptions>();

        Assert.NotNull(options);
        Assert.Equal(ChuAAuthenticationDefaults.Auth0Provider, options.GetDefaultProviderOptions().Type);
        Assert.Equal("dev-example.us.auth0.com", options.GetDefaultProviderOptions().Domain);
        Assert.Equal("https://trust-account-api", options.Audience);
        Assert.Equal("roles", options.RoleClaimType);
        Assert.Equal("permissions", options.PermissionClaimType);
        Assert.Equal("account:create", options.Policies[0].RequiredPermissions.Single());
        Assert.Equal("AccountAdmin", options.Policies[1].RequiredRoles.Single());
    }

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();
}
