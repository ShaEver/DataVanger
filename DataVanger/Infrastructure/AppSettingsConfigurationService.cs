using DataVanger.Core;
using DataVanger.Core.Abstractions;

namespace DataVanger.Infrastructure;

/// <summary>
/// File-backed <see cref="IConfigurationService"/>. Persists to the same
/// <c>appsettings.json</c> path the legacy <see cref="AppSettings"/> loader
/// used, so existing user settings are picked up unchanged.
/// </summary>
public sealed class AppSettingsConfigurationService : IConfigurationService
{
    public AppSettingsConfigurationService(string settingsPath) { SettingsPath = settingsPath; }

    public string SettingsPath { get; }

    public AppSettings Load() => AppSettings.Load(SettingsPath);

    public void Save(AppSettings settings) => settings.Save(SettingsPath);
}
