// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using ChuA.Authentication.Extensions;
using ChuA.Authentication.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace ChuA.Authentication.Tests;

public sealed class ProviderSelectionTests
{
    [Fact]
    public void AddChuAAuthenticationUsesJwtBearerForAuth0()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:Provider"] = "Auth0",
            ["ChuAAuthentication:Domain"] = "dev-example.us.auth0.com",
            ["ChuAAuthentication:Audience"] = "api://trust"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, options.DefaultAuthenticateScheme);
        Assert.Equal(JwtBearerDefaults.AuthenticationScheme, options.DefaultChallengeScheme);

        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
        Assert.Equal("https://dev-example.us.auth0.com", jwtOptions.Authority);
    }

    [Fact]
    public void AddChuAAuthenticationUsesApiKeySchemeForApiKeyProvider()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:Provider"] = "ApiKey",
            ["ChuAAuthentication:ApiKey"] = "local-test-key"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        Assert.Equal(ChuAAuthenticationDefaults.ApiKeyScheme, options.DefaultAuthenticateScheme);
    }

    [Fact]
    public void AddChuAAuthenticationUsesNamedGenericOidcProvider()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:DefaultProvider"] = "CompanyOidc",
            ["ChuAAuthentication:Providers:CompanyOidc:Type"] = "GenericOidc",
            ["ChuAAuthentication:Providers:CompanyOidc:Scheme"] = "CompanyBearer",
            ["ChuAAuthentication:Providers:CompanyOidc:Authority"] = "https://idp.company.com",
            ["ChuAAuthentication:Providers:CompanyOidc:Audience"] = "api://enterprise-api",
            ["ChuAAuthentication:Providers:CompanyOidc:ValidIssuer"] = "https://idp.company.com"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var authenticationOptions = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("CompanyBearer");

        Assert.Equal("CompanyBearer", authenticationOptions.DefaultAuthenticateScheme);
        Assert.Equal("https://idp.company.com", jwtOptions.Authority);
        Assert.Equal("api://enterprise-api", jwtOptions.Audience);
    }

    [Fact]
    public void AddChuAAuthenticationUsesGenericJwtProvider()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "GenericJwt",
            ["ChuAAuthentication:Authority"] = "https://issuer.example.com",
            ["ChuAAuthentication:Audience"] = "api://generic"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://issuer.example.com", jwtOptions.Authority);
        Assert.Equal("api://generic", jwtOptions.Audience);
    }

    [Fact]
    public void AddChuAAuthenticationUsesEntraIdPreset()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "EntraId",
            ["ChuAAuthentication:TenantId"] = "contoso.onmicrosoft.com",
            ["ChuAAuthentication:Audience"] = "api://entra-api"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0", jwtOptions.Authority);
    }

    [Fact]
    public void AddChuAAuthenticationUsesActiveDirectoryPreset()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "ActiveDirectory",
            ["ChuAAuthentication:Authority"] = "https://adfs.company.com/adfs",
            ["ChuAAuthentication:Audience"] = "api://adfs-api"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://adfs.company.com/adfs", jwtOptions.Authority);
    }

    [Fact]
    public void AddChuAAuthenticationPreservesLegacyStandardJwtProviderConfiguration()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:Provider"] = "StandardJwt",
            ["ChuAAuthentication:Authority"] = "https://issuer.example.com",
            ["ChuAAuthentication:Audience"] = "api://legacy"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        Assert.Equal("https://issuer.example.com", jwtOptions.Authority);
        Assert.Equal("api://legacy", jwtOptions.Audience);
    }

    [Fact]
    public void AddChuAAuthenticationSupportsExternallyRegisteredCustomProvider()
    {
        CustomProviderConfigurator.WasConfigured = false;
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationProviderConfigurator, CustomProviderConfigurator>();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "CustomProvider",
            ["ChuAAuthentication:DefaultScheme"] = "CustomScheme"
        });

        services.AddChuAAuthentication(configuration);
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        Assert.True(CustomProviderConfigurator.WasConfigured);
        Assert.Equal("CustomScheme", options.DefaultAuthenticateScheme);
    }

    [Fact]
    public void AddChuAAuthenticationFailsForUnknownProvider()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "UnknownProvider",
            ["ChuAAuthentication:Audience"] = "api://trust",
            ["ChuAAuthentication:ValidIssuer"] = "https://issuer.example.com"
        });

        var exception = Assert.Throws<InvalidOperationException>(() => services.AddChuAAuthentication(configuration));

        Assert.Contains("UnknownProvider", exception.Message);
    }

    [Fact]
    public void AddChuAAuthenticationFailsWhenJwtRequiredSettingsAreMissing()
    {
        var services = new ServiceCollection();
        var configuration = BuildConfiguration(new Dictionary<string, string?>
        {
            ["ChuAAuthentication:ProviderName"] = "GenericJwt"
        });

        var exception = Assert.Throws<InvalidOperationException>(() => services.AddChuAAuthentication(configuration));

        Assert.Contains("requires Authority, ValidIssuer, or ValidIssuers", exception.Message);
    }

    private static IConfiguration BuildConfiguration(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private sealed class CustomProviderConfigurator : IAuthenticationProviderConfigurator
    {
        public static bool WasConfigured { get; set; }

        public string ProviderType => "CustomProvider";

        public void Configure(AuthenticationBuilder builder, ChuAAuthenticationOptions options, ChuAProviderOptions provider)
        {
            WasConfigured = true;
            builder.AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(provider.Scheme!, configureOptions: null);
        }
    }

    private sealed class TestAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
