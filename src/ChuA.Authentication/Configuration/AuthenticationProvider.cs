// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

namespace ChuA.Authentication.Configuration;

public enum AuthenticationProvider
{
    StandardJwt,
    Auth0,
    EntraId,
    ActiveDirectory,
    CloudProvider,
    ApiKey
}
