// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

namespace ChuA.Authentication.Abstractions;

public interface IApiKeyValidator
{
    ValueTask<bool> IsValidAsync(string apiKey, CancellationToken cancellationToken = default);
}
