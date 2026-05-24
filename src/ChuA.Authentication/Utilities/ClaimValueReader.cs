// Copyright (c) 2026 Alvin Wilsen Chan Chua
// GitHub: chuaalvw-y
// Licensed under the Alvin Wilsen Chan Chua Proprietary Use-Only License.
// See LICENSE.txt in the project root for full license information.

using System.Security.Claims;
using System.Text.Json;

namespace ChuA.Authentication.Utilities;

internal static class ClaimValueReader
{
    public static IReadOnlyCollection<string> ReadValues(ClaimsPrincipal principal, params string[] claimTypes)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var claim in principal.Claims.Where(claim => claimTypes.Contains(claim.Type, StringComparer.OrdinalIgnoreCase)))
        {
            foreach (var value in SplitClaimValue(claim.Value))
            {
                values.Add(value);
            }
        }

        return values.ToArray();
    }

    private static IEnumerable<string> SplitClaimValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            yield break;
        }

        if (value.TrimStart().StartsWith('['))
        {
            foreach (var item in TryReadJsonArray(value))
            {
                yield return item;
            }

            yield break;
        }

        foreach (var item in value.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return item;
        }
    }

    private static IEnumerable<string> TryReadJsonArray(string value)
    {
        JsonDocument? document = null;

        try
        {
            document = JsonDocument.Parse(value);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            return document.RootElement
                .EnumerateArray()
                .Where(static element => element.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(element.GetString()))
                .Select(static element => element.GetString()!)
                .ToArray();
        }
        catch (JsonException)
        {
            return [];
        }
        finally
        {
            document?.Dispose();
        }
    }
}
