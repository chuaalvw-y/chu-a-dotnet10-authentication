// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Claims;
using ChuA.Authentication.Configuration;
using ChuA.Authentication.Constants;
using ChuA.Authentication.Handlers;
using ChuA.Authentication.Providers;
using ChuA.Authentication.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ChuA.Authentication.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddChuAAuthentication(this IServiceCollection services, IConfiguration configuration)
        => services.AddChuAAuthentication(configuration, ChuAAuthenticationDefaults.ConfigurationSectionName);

    public static IServiceCollection AddChuAAuthentication(this IServiceCollection services, IConfiguration configuration, string sectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(sectionName);

        var section = configuration.GetSection(sectionName);
        var options = section.Get<ChuAAuthenticationOptions>() ?? new ChuAAuthenticationOptions();
        var providerOptions = options.GetDefaultProviderOptions();

        services.Configure<ChuAAuthenticationOptions>(section);
        services.AddHttpContextAccessor();
        services.AddChuAAuthenticationServices();

        var defaultScheme = ResolveDefaultScheme(options, providerOptions);

        var builder = services.AddAuthentication(authenticationOptions =>
        {
            authenticationOptions.DefaultAuthenticateScheme = defaultScheme;
            authenticationOptions.DefaultChallengeScheme = defaultScheme;
            authenticationOptions.DefaultScheme = defaultScheme;
        });

        using var temporaryProvider = services.BuildServiceProvider();
        var configurator = temporaryProvider
            .GetServices<IAuthenticationProviderConfigurator>()
            .LastOrDefault(configurator => configurator.CanConfigure(providerOptions));

        if (configurator is null)
        {
            throw new InvalidOperationException($"No ChuA authentication provider configurator is registered for provider type '{providerOptions.Type}'.");
        }

        providerOptions.Scheme ??= defaultScheme;
        configurator.Configure(builder, options, providerOptions);

        if (options.EnableClaimsTransformation)
        {
            services.AddTransient<IClaimsTransformation, ChuAClaimsTransformation>();
        }

        return services.AddChuAAuthorizationPolicies(configuration, sectionName);
    }

    public static IServiceCollection AddChuAAuthorizationPolicies(this IServiceCollection services, IConfiguration configuration)
        => services.AddChuAAuthorizationPolicies(configuration, ChuAAuthenticationDefaults.ConfigurationSectionName);

    public static IServiceCollection AddChuAAuthorizationPolicies(this IServiceCollection services, IConfiguration configuration, string sectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = configuration.GetSection(sectionName).Get<ChuAAuthenticationOptions>() ?? new ChuAAuthenticationOptions();
        var policyBuilderService = new AuthorizationPolicyProviderService();

        services.AddAuthorization(authorizationOptions =>
        {
            foreach (var policy in options.Policies.Where(static policy => !string.IsNullOrWhiteSpace(policy.Name)))
            {
                authorizationOptions.AddPolicy(policy.Name, policyBuilderService.BuildPolicy(policy));
            }

            if (options.RequireAuthenticatedUserByDefault)
            {
                authorizationOptions.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            }
        });

        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();

        return services;
    }

    private static IServiceCollection AddChuAAuthenticationServices(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, JwtAuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, GenericOidcAuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, Auth0AuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, EntraIdAuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, ActiveDirectoryAuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, CloudProviderAuthenticationProviderConfigurator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthenticationProviderConfigurator, ApiKeyAuthenticationProviderConfigurator>());
        services.AddScoped<ICurrentUserContext, CurrentUserContext>();
        services.AddSingleton<IClaimsMappingService, ClaimsMappingService>();
        services.AddSingleton<IPermissionService, PermissionService>();
        services.AddSingleton<IRoleService, RoleService>();
        services.AddSingleton<IAuthorizationPolicyProviderService, AuthorizationPolicyProviderService>();
        services.AddSingleton<ITokenValidationService, TokenValidationService>();
        services.AddSingleton<IApiKeyValidator, ConfiguredApiKeyValidator>();

        return services;
    }

    private static string ResolveDefaultScheme(ChuAAuthenticationOptions options, ChuAProviderOptions provider)
    {
        if (!string.IsNullOrWhiteSpace(provider.Scheme))
        {
            return provider.Scheme;
        }

        if (!string.IsNullOrWhiteSpace(options.DefaultScheme))
        {
            return options.DefaultScheme;
        }

        return string.Equals(provider.Type, ChuAAuthenticationDefaults.ApiKeyProvider, StringComparison.OrdinalIgnoreCase)
            ? ChuAAuthenticationDefaults.ApiKeyScheme
            : JwtBearerDefaults.AuthenticationScheme;
    }
}
