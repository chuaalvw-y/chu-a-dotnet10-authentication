// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using ChuA.Authentication.Abstractions;
using ChuA.Authentication.Configuration;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace ChuA.Authentication.Services;

public sealed class ConfiguredApiKeyValidator(IOptions<ChuAAuthenticationOptions> options) : IApiKeyValidator
{
    public ValueTask<bool> IsValidAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var configuredApiKey = options.Value.GetDefaultProviderOptions().ApiKey;
        if (string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(configuredApiKey))
        {
            return ValueTask.FromResult(false);
        }

        var presented = Encoding.UTF8.GetBytes(apiKey);
        var configured = Encoding.UTF8.GetBytes(configuredApiKey);

        return ValueTask.FromResult(presented.Length == configured.Length && CryptographicOperations.FixedTimeEquals(presented, configured));
    }
}
