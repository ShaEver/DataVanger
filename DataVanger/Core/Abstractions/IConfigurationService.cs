using DataVanger.Core;

namespace DataVanger.Core.Abstractions;

/// <summary>
/// Persistent configuration store. Wraps the JSON file under
/// <c>%UserProfile%\DataVanger\appsettings.json</c>.
/// </summary>
public interface IConfigurationService
{
    AppSettings Load();
    void Save(AppSettings settings);

    /// <summary>Absolute path of the underlying settings file.</summary>
    string SettingsPath { get; }
}
