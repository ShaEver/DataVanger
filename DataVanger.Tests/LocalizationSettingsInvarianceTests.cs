using System.Text.Json;
using DataVanger.Core;
using DataVanger.Localization;
using Xunit;

// Beta phase 01B — guard required by the phase MD (§9/§10): localization must
// never rename persisted settings keys or serialized members. Serializes
// AppSettings under the en-US scaffold culture and asserts the JSON property
// names remain the culture-invariant identifiers.
public class LocalizationSettingsInvarianceTests
{
    [Fact]
    public void PersistedSettingsKeys_AreCultureInvariant_UnderEnUs()
    {
        LocalizationService.ApplyCulture("en-US");
        try
        {
            var json = JsonSerializer.Serialize(new AppSettings());

            foreach (var key in new[]
            {
                "SchemaVersion",
                "MinScoreToReport",
                "MinScoreToQuarantine",
                "AutoQuarantineKnownMalware",
                "ExcludedPaths",
                "TrustedPublishers",
                "EnableYaraRules",
                "SignedUpdateFeedUrl",
            })
            {
                Assert.Contains("\"" + key + "\"", json);
            }
        }
        finally
        {
            LocalizationService.ApplyCulture(LocalizationService.DefaultCultureName);
        }
    }
}
