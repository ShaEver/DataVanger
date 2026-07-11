using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DataVanger.Shared.Service;

namespace DataVanger.Service.Configuration;

/// <summary>
/// Safe configuration loader for the service runtime.
///
/// Contract:
///   - Missing file => safe defaults + LoadedFromSource=false (no warnings).
///   - Malformed file => safe defaults + LoadedFromSource=false + warning.
///   - Read failure (I/O, access denied) => safe defaults + warning, never throws.
///   - Never writes / mutates user settings during load.
/// </summary>
public static class ServiceConfigurationLoader
{
    public static ServiceConfigurationLoadResult LoadFromFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return new ServiceConfigurationLoadResult(
                DataVangerServiceConfiguration.SafeDefaults(),
                loadedFromSource: false,
                warnings: Array.Empty<string>());
        }

        if (!File.Exists(path))
        {
            return new ServiceConfigurationLoadResult(
                DataVangerServiceConfiguration.SafeDefaults(),
                loadedFromSource: false,
                warnings: Array.Empty<string>());
        }

        string text;
        try
        {
            text = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ServiceConfigurationLoadResult(
                DataVangerServiceConfiguration.SafeDefaults(),
                loadedFromSource: false,
                warnings: new[] { $"Configuration read failed: {ex.GetType().Name}. Using safe defaults." });
        }

        return ParseJsonOrDefault(text);
    }

    public static ServiceConfigurationLoadResult ParseJsonOrDefault(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new ServiceConfigurationLoadResult(
                DataVangerServiceConfiguration.SafeDefaults(),
                loadedFromSource: false,
                warnings: Array.Empty<string>());
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<DataVangerServiceConfiguration>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (parsed is null)
            {
                return new ServiceConfigurationLoadResult(
                    DataVangerServiceConfiguration.SafeDefaults(),
                    loadedFromSource: false,
                    warnings: new[] { "Configuration parsed as null. Using safe defaults." });
            }

            return new ServiceConfigurationLoadResult(
                parsed,
                loadedFromSource: true,
                warnings: Array.Empty<string>());
        }
        catch (JsonException)
        {
            return new ServiceConfigurationLoadResult(
                DataVangerServiceConfiguration.SafeDefaults(),
                loadedFromSource: false,
                warnings: new[] { "Configuration JSON was malformed. Using safe defaults." });
        }
    }
}
