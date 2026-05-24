# ChuA.Authentication

Enterprise-ready reusable authentication and authorization helpers for .NET 10 applications.

`ChuA.Authentication` keeps application startup code consistent while supporting provider-agnostic JWT/OIDC authentication, Auth0, Microsoft Entra ID, Active Directory / ADFS-style JWTs, custom provider configurators, and optional API key authentication for internal service-to-service scenarios.

## Install

Reference the library project or package:

```xml
<ProjectReference Include="..\src\ChuA.Authentication\ChuA.Authentication.csproj" />
```

## Program.cs

```csharp
using ChuA.Authentication.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddChuAAuthentication(builder.Configuration);

var app = builder.Build();

app.UseHttpsRedirection();
app.UseChuAAuthentication();
app.MapControllers();

app.Run();
```

Use a custom configuration section when needed:

```csharp
builder.Services.AddChuAAuthentication(builder.Configuration, "Security:Authentication");
```

## Provider Model

The library selects authentication providers by string provider keys instead of requiring core library changes for every identity provider.

Built-in provider types:

- `GenericJwt`
- `GenericOidc`
- `Auth0`
- `EntraId`
- `ActiveDirectory`
- `CloudProvider`
- `ApiKey`

Use `ProviderName` for a single provider, or `DefaultProvider` plus `Providers` for named provider configuration.

```json
{
  "ChuAAuthentication": {
    "DefaultScheme": "Bearer",
    "ProviderName": "GenericOidc",
    "Authority": "https://login.example.com",
    "Audience": "api://my-api",
    "ValidIssuer": "https://login.example.com",
    "RequireHttpsMetadata": true,
    "Claims": {
      "UserIdClaimTypes": [ "sub", "oid", "nameidentifier" ],
      "UserNameClaimTypes": [ "preferred_username", "email", "upn", "name" ],
      "RoleClaimTypes": [ "roles", "role", "groups" ],
      "ScopeClaimTypes": [ "scope", "scp" ]
    }
  }
}
```

Named providers:

```json
{
  "ChuAAuthentication": {
    "DefaultProvider": "CompanyOidc",
    "Providers": {
      "CompanyOidc": {
        "Type": "GenericOidc",
        "Scheme": "Bearer",
        "Authority": "https://idp.company.com",
        "Audience": "api://enterprise-api",
        "ValidIssuer": "https://idp.company.com",
        "RequireHttpsMetadata": true
      },
      "InternalApiKey": {
        "Type": "ApiKey",
        "Scheme": "ApiKey",
        "HeaderName": "X-API-Key"
      }
    }
  }
}
```

## Generic JWT

```json
{
  "ChuAAuthentication": {
    "ProviderName": "GenericJwt",
    "Authority": "https://issuer.example.com",
    "Audience": "trust-account-api",
    "ValidIssuer": "https://issuer.example.com",
    "ValidAudiences": [ "trust-account-api" ],
    "RequireHttpsMetadata": true
  }
}
```

## Generic OIDC

```json
{
  "ChuAAuthentication": {
    "ProviderName": "GenericOidc",
    "Authority": "https://login.example.com",
    "MetadataAddress": "https://login.example.com/.well-known/openid-configuration",
    "Audience": "api://my-api",
    "ValidIssuer": "https://login.example.com",
    "RequireHttpsMetadata": true
  }
}
```

## Auth0 Preset

```json
{
  "ChuAAuthentication": {
    "ProviderName": "Auth0",
    "Domain": "dev-example.us.auth0.com",
    "Audience": "https://trust-account-api",
    "Claims": {
      "RoleClaimTypes": [ "roles" ],
      "PermissionClaimTypes": [ "permissions" ],
      "ScopeClaimTypes": [ "scope" ]
    },
    "RequireHttpsMetadata": true,
    "Policies": [
      {
        "Name": "CanCreateAccount",
        "RequiredPermissions": [ "account:create" ]
      },
      {
        "Name": "CanAdministerAccount",
        "RequiredRoles": [ "AccountAdmin" ]
      }
    ]
  }
}
```

## Microsoft Entra ID Preset

```json
{
  "ChuAAuthentication": {
    "ProviderName": "EntraId",
    "TenantId": "00000000-0000-0000-0000-000000000000",
    "Audience": "api://trust-account-api",
    "Claims": {
      "RoleClaimTypes": [ "roles", "groups" ],
      "ScopeClaimTypes": [ "scp" ]
    },
    "RequireHttpsMetadata": true,
    "Policies": [
      {
        "Name": "CanReadAccounts",
        "RequiredScopes": [ "Account.Read" ]
      }
    ]
  }
}
```

## Active Directory / ADFS Preset

```json
{
  "ChuAAuthentication": {
    "ProviderName": "ActiveDirectory",
    "Authority": "https://adfs.company.com/adfs",
    "Audience": "api://enterprise-api",
    "ValidIssuer": "https://adfs.company.com/adfs",
    "RequireHttpsMetadata": true
  }
}
```

## API Key

API key mode is intended for internal service-to-service scenarios. Store the key in user secrets, Key Vault, environment variables, or another secret provider. Do not commit it to source control.

```json
{
  "ChuAAuthentication": {
    "ProviderName": "ApiKey",
    "DefaultScheme": "ApiKey",
    "ApiKeyHeaderName": "X-API-Key",
    "ApiKey": "<secret-from-secure-configuration>"
  }
}
```

## Custom Provider Configurator

Register a custom configurator before calling `AddChuAAuthentication`.

```csharp
using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using Microsoft.AspNetCore.Authentication;

public sealed class CompanyAuthenticationProviderConfigurator : IAuthenticationProviderConfigurator
{
    public string ProviderType => "CompanyProvider";

    public void Configure(
        AuthenticationBuilder builder,
        ChuAAuthenticationOptions options,
        ChuAProviderOptions provider)
    {
        builder.AddJwtBearer(provider.Scheme ?? "Bearer", jwt =>
        {
            jwt.Authority = provider.Authority;
            jwt.Audience = provider.Audience;
            jwt.RequireHttpsMetadata = provider.RequireHttpsMetadata;
            jwt.TokenValidationParameters = options.BuildTokenValidationParameters(provider);
        });
    }
}
```

```csharp
builder.Services.AddSingleton<IAuthenticationProviderConfigurator, CompanyAuthenticationProviderConfigurator>();
builder.Services.AddChuAAuthentication(builder.Configuration);
```

```json
{
  "ChuAAuthentication": {
    "ProviderName": "CompanyProvider",
    "DefaultScheme": "Bearer",
    "Authority": "https://idp.company.com",
    "Audience": "api://enterprise-api",
    "ValidIssuer": "https://idp.company.com"
  }
}
```

## Controllers

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("accounts")]
[Authorize]
public sealed class AccountsController : ControllerBase
{
    [HttpPost]
    [Authorize(Policy = "CanCreateAccount")]
    public IActionResult Create() => Ok();

    [HttpGet("admin")]
    [Authorize(Policy = "CanAdministerAccount")]
    public IActionResult Admin() => Ok();
}
```

## Current User Context

```csharp
using ChuA.Authentication.Abstractions;

public sealed class AccountService(ICurrentUserContext currentUser)
{
    public bool CanCreateAccount()
        => currentUser.IsAuthenticated
           && currentUser.HasPermission("account:create");
}
```

`ICurrentUserContext` exposes `UserId`, `UserName`, `Email`, `Roles`, `Permissions`, `Scopes`, raw `Claims`, `IsAuthenticated`, and helper methods for roles, permissions, and scopes.

## Secure Defaults

- HTTPS metadata is required by default.
- JWTs require issuer validation, audience validation, expiration, signed tokens, signing key validation, and lifetime validation by default.
- Tokens and secrets are not logged by the library.
- API key comparison uses fixed-time comparison and fails closed when no configured key exists.
- Authorization fallback policy requires authenticated users by default.

## Migration Notes

The legacy enum-based `Provider` setting still works:

```json
{
  "ChuAAuthentication": {
    "Provider": "Auth0",
    "Domain": "dev-example.us.auth0.com",
    "Audience": "https://trust-account-api"
  }
}
```

For new applications, prefer string-based provider selection:

```json
{
  "ChuAAuthentication": {
    "ProviderName": "Auth0",
    "Domain": "dev-example.us.auth0.com",
    "Audience": "https://trust-account-api"
  }
}
```

`Provider = StandardJwt` maps to `ProviderName = GenericJwt`. `Provider = CloudProvider` maps to the generic cloud/OIDC-style JWT preset. Provider-specific authority conveniences such as Auth0 `Domain` and Entra `TenantId` now live in preset configurators rather than the core options model.

## License

Copyright (c) 2026 Alvin Wilsen Chan Chua.  
GitHub: chuaalvw-y

This project is licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.

You may use this software for personal, educational, or internal evaluation purposes only. You may not modify, sell, sublicense, redistribute, publish, or include this software in a commercial product or service without prior written permission.

See [LICENSE.txt](LICENSE.txt) for full license details.
