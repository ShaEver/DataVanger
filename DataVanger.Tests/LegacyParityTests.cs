using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DataVanger.Classification;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
using DataVanger.Core.Domain;
using DataVanger.Detection;
using DataVanger.Engine;
using DataVanger.Memory;
using DataVanger.Memory.Readers;
using DataVanger.Memory.Rules;
using DataVanger.Reputation;
using static DataVanger.Tests.Fixtures.PeFactory;



// ── Phase 2 / Step 09: Module Status and UI Settings test section ────────────
// Decomposed (phase 09): invoked as a dedicated [Fact] by ModuleStatusTests. Promoted
// from file-local to internal so the per-subsystem test class can call Run(...).
internal static class Phase09ModuleStatusUiSettings
{
    public static void Run(Action<bool, string> assert)
    {
        // 1. Module status model construction.
        {
            var phase09ModuleStatus = new DataVanger.Shared.Status.ModuleStatus(
                "phase09-scanner",
                "Scanner",
                DataVanger.Shared.Status.ModuleOperatingState.Active,
                "On-demand scanner available.",
                contributesToActiveProtection: false);
            assert(phase09ModuleStatus.Key == "phase09-scanner"
                   && phase09ModuleStatus.DisplayName == "Scanner"
                   && phase09ModuleStatus.State == DataVanger.Shared.Status.ModuleOperatingState.Active
                   && !phase09ModuleStatus.IsActiveProtection,
                "Phase09 ModuleStatus must construct without claiming active protection by default.");
        }

        // 2. Product health snapshot aggregation.
        {
            var phase09ProductSnapshot = DataVanger.Shared.Status.ProductHealthSnapshot.FromModules(new[]
            {
                new DataVanger.Shared.Status.ModuleStatus("phase09-active", "Active module",
                    DataVanger.Shared.Status.ModuleOperatingState.Active, "Active.", contributesToActiveProtection: true),
                new DataVanger.Shared.Status.ModuleStatus("phase09-disabled", "Disabled module",
                    DataVanger.Shared.Status.ModuleOperatingState.Disabled, "Disabled."),
            }, DateTimeOffset.UnixEpoch);
            assert(phase09ProductSnapshot.State == DataVanger.Shared.Status.ProductHealthState.Partial
                   && phase09ProductSnapshot.HasActiveProtection
                   && !phase09ProductSnapshot.IsFullyProtected
                   && phase09ProductSnapshot.DisabledModuleCount == 1,
                "Phase09 ProductHealthSnapshot must not claim fully protected when any module is disabled.");
        }

        // 3/4/5. Disabled, degraded, and unsupported module status semantics.
        {
            var phase09DisabledStatus = new DataVanger.Shared.Status.ModuleStatus(
                "phase09-disabled", "Disabled", DataVanger.Shared.Status.ModuleOperatingState.Disabled, "Disabled.");
            var phase09DegradedStatus = new DataVanger.Shared.Status.ModuleStatus(
                "phase09-degraded", "Degraded", DataVanger.Shared.Status.ModuleOperatingState.Degraded, "Degraded.");
            var phase09UnsupportedStatus = new DataVanger.Shared.Status.ModuleStatus(
                "phase09-unsupported", "Unsupported", DataVanger.Shared.Status.ModuleOperatingState.Unsupported, "Unsupported.");
            assert(!phase09DisabledStatus.IsActiveProtection
                   && !phase09DegradedStatus.IsActiveProtection
                   && !phase09UnsupportedStatus.IsActiveProtection,
                "Phase09 disabled/degraded/unsupported statuses must never be active protection.");
        }

        // 6. Test-only/mock provider status.
        {
            var phase09AggregatorWithNullProvider = new DataVanger.Engine.Status.ModuleStatusAggregator(
                new DataVanger.Engine.Status.IModuleStatusProvider?[] { null! });
            var phase09ModuleStatuses = phase09AggregatorWithNullProvider.GetModuleStatuses();
            assert(phase09ModuleStatuses.Count == 1
                   && phase09ModuleStatuses[0].State == DataVanger.Shared.Status.ModuleOperatingState.TestOnly
                   && !phase09ModuleStatuses[0].IsActiveProtection,
                "Phase09 null/mock providers must be surfaced as TestOnly, not active protection.");
        }

        // 7. Development mode status.
        {
            var phase09Settings = DataVanger.Shared.Settings.DataVangerSettings.DevelopmentSafeDefaults() with
            {
                SelfProtectionRequested = true,
            };
            var phase09ModuleStatuses = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders(phase09Settings)).GetModuleStatuses();
            var phase09SelfProtectionStatus = phase09ModuleStatuses.Single(m => m.Key == "self-protection");
            assert(phase09SelfProtectionStatus.State == DataVanger.Shared.Status.ModuleOperatingState.Passive
                   && phase09SelfProtectionStatus.Detail.Contains("Development-safe", StringComparison.OrdinalIgnoreCase),
                "Phase09 self-protection in development mode must be passive/development-safe.");
        }

        // 8. Invalid configuration downgrade.
        {
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(
                new DataVanger.Shared.Settings.DataVangerSettings
                {
                    AutomaticQuarantineRequested = true,
                    AutomaticQuarantineForNonConfirmedMalwareRequested = true,
                });
            assert(!phase09ValidationResult.IsValid
                   && !phase09ValidationResult.EffectiveSettings.AutomaticQuarantineForNonConfirmedMalwareRequested
                   && phase09ValidationResult.Issues.Any(i => i.Code == "AutomaticQuarantineConfirmedOnly"),
                "Phase09 settings validation must safely downgrade non-confirmed automatic quarantine.");
        }

        // 9. Service unavailable status.
        {
            var phase09Settings = DataVanger.Shared.Settings.DataVangerSettings.DevelopmentSafeDefaults() with
            {
                ActiveRealtimeProtectionRequested = true,
                ServiceAvailable = false,
            };
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(phase09Settings);
            var phase09ModuleStatuses = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders(phase09Settings)).GetModuleStatuses();
            var phase09RealtimeStatus = phase09ModuleStatuses.Single(m => m.Key == "realtime-file-protection");
            assert(phase09ValidationResult.Issues.Any(i => i.Code == "ServiceUnavailable")
                   && phase09RealtimeStatus.State == DataVanger.Shared.Status.ModuleOperatingState.Degraded,
                "Phase09 active realtime requested without service must become warning/degraded status.");
        }

        // 10. ETW unavailable status.
        {
            var phase09Settings = DataVanger.Shared.Settings.DataVangerSettings.DevelopmentSafeDefaults() with
            {
                EtwTelemetryRequested = true,
                EtwProviderSupported = false,
            };
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(phase09Settings);
            var phase09EtwStatus = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders(phase09Settings))
                .GetModuleStatuses()
                .Single(m => m.Key == "etw-telemetry");
            assert(phase09ValidationResult.Issues.Any(i => i.Code == "EtwUnavailable")
                   && phase09EtwStatus.State == DataVanger.Shared.Status.ModuleOperatingState.Unavailable,
                "Phase09 ETW requested on unsupported provider must be warning/unavailable.");
        }

        // 11. Protected Files Activity alert-only status.
        {
            var phase09Settings = DataVanger.Shared.Settings.DataVangerSettings.DevelopmentSafeDefaults() with
            {
                ProtectedFilesActivityRequested = true,
                RuntimeEventPipelineEnabled = true,
            };
            var phase09ProtectedFilesStatus = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders(phase09Settings))
                .GetModuleStatuses()
                .Single(m => m.Key == "protected-files-activity");
            assert(phase09ProtectedFilesStatus.State == DataVanger.Shared.Status.ModuleOperatingState.AlertOnly
                   && !phase09ProtectedFilesStatus.IsActiveProtection,
                "Phase09 Protected Files Activity must be alert-only and never active remediation from status.");
        }

        // 12. Update system is a truthful placeholder before Signed Updates.
        {
            var phase09UpdateStatus = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders())
                .GetModuleStatuses()
                .Single(m => m.Key == "updates");
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(
                DataVanger.Shared.Settings.DataVangerSettings.DevelopmentSafeDefaults() with
                {
                    Updates = new DataVanger.Shared.Settings.UpdateSettings
                    {
                        SignedUpdateValidationRequested = true,
                        SignedUpdatesImplemented = false,
                        SignedUpdatesConfigured = false,
                    },
                });
            assert(phase09UpdateStatus.State == DataVanger.Shared.Status.ModuleOperatingState.NotImplemented
                   && phase09ValidationResult.Issues.Any(i => i.Code == "SignedUpdatesNotConfigured")
                   && !phase09ValidationResult.EffectiveSettings.Updates.SignedUpdateValidationRequested,
                "Phase09 Signed Updates must remain NotImplemented/NotConfigured placeholders.");
        }

        // 13. Automatic quarantine cannot bypass ConfirmedMalware policy.
        {
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(
                new DataVanger.Shared.Settings.DataVangerSettings
                {
                    AutomaticQuarantineRequested = true,
                    AutomaticQuarantineForNonConfirmedMalwareRequested = true,
                });
            assert(phase09ValidationResult.Issues.Any(i => i.Severity == DataVanger.Shared.Settings.SettingsIssueSeverity.Invalid)
                   && !phase09ValidationResult.EffectiveSettings.AutomaticQuarantineForNonConfirmedMalwareRequested,
                "Phase09 automatic quarantine settings must preserve ConfirmedMalware-only policy.");
        }

        // 14. UI-facing model and visible UI do not display version-number branding.
        {
            var phase09ProductSnapshot = DataVanger.Shared.Status.ProductHealthSnapshot.FromModules(new[]
            {
                new DataVanger.Shared.Status.ModuleStatus("phase09-disabled", "Disabled",
                    DataVanger.Shared.Status.ModuleOperatingState.Disabled, "Disabled."),
            });
            var phase09ProductViewModel = DataVanger.Shared.Status.ProductHealthViewModel.FromSnapshot(phase09ProductSnapshot);
            var phase09MainWindowXaml = File.ReadAllText(Phase09FindRepoFile("DataVanger", "MainWindow.xaml"));
            assert(phase09ProductViewModel.ProductName == "DataVanger"
                   && phase09MainWindowXaml.Contains("Title=\"DataVanger\"", StringComparison.Ordinal)
                   && phase09MainWindowXaml.Contains("Text=\"DataVanger\"", StringComparison.Ordinal)
                   && !phase09MainWindowXaml.Contains("DataVanger v3.0", StringComparison.OrdinalIgnoreCase)
                   && !phase09MainWindowXaml.Contains("DataVanger v2.0", StringComparison.OrdinalIgnoreCase)
                   && !phase09MainWindowXaml.Contains("v3.0", StringComparison.OrdinalIgnoreCase)
                   && !phase09MainWindowXaml.Contains("v2.0", StringComparison.OrdinalIgnoreCase),
                "Phase09 visible UI branding must be exactly DataVanger without visible version numbers.");
        }

        // 15. Status read does not start background loops.
        {
            var phase09CountingProvider = new Phase09CountingStatusProvider();
            var phase09ModuleStatuses = new DataVanger.Engine.Status.ModuleStatusAggregator(new[] { phase09CountingProvider })
                .GetModuleStatuses();
            var phase09AggregatorMethods = typeof(DataVanger.Engine.Status.ModuleStatusAggregator).GetMethods()
                .Select(m => m.Name)
                .ToArray();
            assert(phase09ModuleStatuses.Count == 1
                   && phase09CountingProvider.Phase09ReadCount == 1
                   && phase09CountingProvider.Phase09StartCount == 0
                   && !phase09AggregatorMethods.Any(m => m.Contains("Start", StringComparison.OrdinalIgnoreCase)),
                "Phase09 status reads must not start runtime engines, watchers, ETW sessions, scans, or loops.");
        }

        // 16. Status read does not require admin privileges and degrades on provider failure.
        {
            var phase09ModuleStatuses = new DataVanger.Engine.Status.ModuleStatusAggregator(new[]
            {
                new Phase09ThrowingStatusProvider(),
            }).GetModuleStatuses();
            assert(phase09ModuleStatuses.Count == 1
                   && phase09ModuleStatuses[0].State == DataVanger.Shared.Status.ModuleOperatingState.Degraded
                   && !phase09ModuleStatuses[0].IsActiveProtection,
                "Phase09 provider failures must degrade without requiring admin privileges or crashing.");
        }

        // 17. Default catalog covers the current module surface honestly.
        {
            var phase09ModuleStatuses = new DataVanger.Engine.Status.ModuleStatusAggregator(
                DataVanger.Engine.Status.DefaultModuleStatusCatalog.CreateProviders()).GetModuleStatuses();
            var phase09ModuleKeys = phase09ModuleStatuses.Select(m => m.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var phase09ExpectedKey in new[]
                     {
                         "scanner",
                         "realtime-file-protection",
                         "windows-service-host",
                         "runtime-event-pipeline",
                         "etw-telemetry",
                         "behavioral-runtime-binding",
                         "protected-files-activity",
                         "secure-quarantine-v2",
                         "updates",
                         "self-protection",
                         "scheduler",
                         "reporting-forensics",
                         "browser-extension-intelligence",
                         "reputation-engine",
                         "memory-scanner",
                         "amsi-like-analysis",
                     })
            {
                assert(phase09ModuleKeys.Contains(phase09ExpectedKey),
                    "Phase09 default module catalog must include " + phase09ExpectedKey + ".");
            }

            assert(phase09ModuleStatuses.All(m => m.State != DataVanger.Shared.Status.ModuleOperatingState.Active || !m.IsActiveProtection)
                   && !DataVanger.Shared.Status.ProductHealthSnapshot.FromModules(phase09ModuleStatuses).IsFullyProtected,
                "Phase09 default status surface must not claim full resident protection.");
        }

        // 18. Settings validation accepts null/invalid input safely.
        {
            var phase09ValidationResult = DataVanger.Shared.Settings.DataVangerSettingsValidator.Validate(null);
            var phase09SettingsViewModel = DataVanger.Shared.Settings.SettingsViewModel.FromValidation(phase09ValidationResult);
            assert(phase09ValidationResult.IsValid
                   && phase09SettingsViewModel.DevelopmentMode,
                "Phase09 settings validation must not crash on null and must use development-safe defaults.");
        }
    }

    private static string Phase09FindRepoFile(params string[] phase09Parts)
    {
        var phase09Directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (phase09Directory != null)
        {
            var phase09Candidate = Path.Combine(new[] { phase09Directory.FullName }.Concat(phase09Parts).ToArray());
            if (File.Exists(phase09Candidate)) return phase09Candidate;
            phase09Directory = phase09Directory.Parent;
        }

        phase09Directory = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (phase09Directory != null)
        {
            var phase09Candidate = Path.Combine(new[] { phase09Directory.FullName }.Concat(phase09Parts).ToArray());
            if (File.Exists(phase09Candidate)) return phase09Candidate;
            phase09Directory = phase09Directory.Parent;
        }

        throw new FileNotFoundException("Phase09 test file not found: " + string.Join("/", phase09Parts));
    }
}

file sealed class Phase09CountingStatusProvider : DataVanger.Engine.Status.IModuleStatusProvider
{
    public int Phase09ReadCount { get; private set; }
    public int Phase09StartCount { get; private set; }

    public DataVanger.Shared.Status.ModuleStatus GetStatus()
    {
        Phase09ReadCount++;
        return new DataVanger.Shared.Status.ModuleStatus(
            "phase09-counting",
            "Counting provider",
            DataVanger.Shared.Status.ModuleOperatingState.Passive,
            "Read-only test provider.");
    }

    public void Start() => Phase09StartCount++;
}

file sealed class Phase09ThrowingStatusProvider : DataVanger.Engine.Status.IModuleStatusProvider
{
    public DataVanger.Shared.Status.ModuleStatus GetStatus()
        => throw new InvalidOperationException("phase09 status provider failure");
}

// ── Phase 2 / Step 08: Secure Quarantine V2 test section ─────────────────────
// File-local helper so the section introduces no top-level locals. Everything
// here is deterministic: in-memory store + in-memory key protector or a temp
// folder filesystem store; no admin, no DPAPI requirement, no service, no ETW.
//
// xUnit1031-deferred: this is a synchronous, file-local HELPER class invoked by the async
// mega-[Fact] — it is NOT a test method, so its blocking GetAwaiter/GetResult calls are outside
// xUnit1031's scope (the analyzer targets [Fact]/[Theory] bodies). They are kept blocking on
// purpose: the helpers/Run return void/values, so converting them to async would create
// async-void or ripple signature changes. Phase-08 async cleanup applies only to the Fact body.
// Decomposed (phase 09): invoked as a dedicated [Fact] by QuarantineTests. Promoted
// from file-local to internal so the per-subsystem test class can call Run(...).
internal static class Phase08SecureQuarantineV2
{
    // Phase-specific helper aliases to keep the section self-contained.
    private static string Phase08NewTempFile(string content)
    {
        var phase08SourcePath = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "dvq08_src_" + Guid.NewGuid().ToString("N") + ".bin");
        System.IO.File.WriteAllText(phase08SourcePath, content);
        return phase08SourcePath;
    }

    private static DataVanger.Engine.Quarantine.QuarantineService Phase08NewService(
        DataVanger.Shared.Quarantine.IQuarantineStore phase08Store,
        string phase08Seed = "phase08",
        DataVanger.Shared.Quarantine.IQuarantineAuditSink? phase08Sink = null,
        DataVanger.Shared.Quarantine.QuarantineOptions? phase08Options = null,
        string phase08Root = "",
        Action<string>? phase08Remover = null)
        => new(
            phase08Store,
            new DataVanger.Engine.Quarantine.QuarantineCryptoProvider(),
            new DataVanger.Engine.Quarantine.InMemoryQuarantineKeyProtector(phase08Seed),
            phase08Options ?? DataVanger.Shared.Quarantine.QuarantineOptions.DevelopmentSafe(),
            quarantineStoreRoot: phase08Root,
            auditSink: phase08Sink,
            clock: null,
            originalRemover: phase08Remover);

    public static void Run(Action<bool, string> assert)
    {
        var phase08CancellationToken = System.Threading.CancellationToken.None;

        // 1/2/3. Authenticated storage + record metadata + intact verify.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("PHASE08-SECRET-CONTENT-XYZ");
            var phase08PlainBytes = System.IO.File.ReadAllBytes(phase08SourcePath);
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08SourcePath,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.ManualUserApproved,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success,
                "Quarantine V2 stores a file successfully.");

            var phase08StoredPayload = phase08Store.ReadPayloadAsync(phase08QuarantineResult.Record!.PayloadName, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08StoredPayload != null && phase08StoredPayload!.Nonce.Length == 12 && phase08StoredPayload.Tag.Length == 16,
                "Quarantine V2 payload is AES-GCM authenticated (12B nonce, 16B tag).");
            assert(!phase08StoredPayload!.CipherText.SequenceEqual(phase08PlainBytes),
                "Quarantine V2 payload ciphertext differs from plaintext (encrypted at rest).");

            var phase08Record = phase08Service.GetAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08Record != null && phase08Record!.OriginalSha256.Length == 64
                   && phase08Record.PayloadEncryptionAlgorithm == "AES-256-GCM"
                   && phase08Record.MetadataIntegrityAlgorithm == "HMACSHA256"
                   && phase08Record.SchemaVersion == 2
                   && phase08Record.KeyProtectionMode == DataVanger.Shared.Quarantine.QuarantineKeyProtectionMode.InMemory,
                "Quarantine V2 record carries expected versioned metadata.");

            var phase08IntegrityResult = phase08Service.VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08IntegrityResult.IsIntact, "Quarantine V2 verifies an intact payload.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 4. Payload tamper detection.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-payload-tamper");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            phase08Store.TamperPayloadRaw(phase08QuarantineResult.Record!.PayloadName, phase08Raw =>
            {
                var phase08Mutated = (byte[])phase08Raw.Clone();
                phase08Mutated[phase08Mutated.Length - 1] ^= 0xFF;
                return phase08Mutated;
            });
            var phase08IntegrityResult = phase08Service.VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08IntegrityResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.IntegrityCheckFailed && !phase08IntegrityResult.PayloadIntact,
                "Quarantine V2 detects payload tampering (IntegrityCheckFailed, not a malware verdict).");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 5. Metadata tamper detection + restore refusal.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-metadata-tamper");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            phase08Store.TamperRecordJson(phase08QuarantineResult.QuarantineId!, phase08Json =>
            {
                var phase08Envelope = DataVanger.Shared.Quarantine.QuarantineRecordSerializer.DeserializeEnvelope(phase08Json)!;
                var phase08RecordModel = DataVanger.Shared.Quarantine.QuarantineRecordSerializer.DeserializeRecord(phase08Envelope.GetRecordBytes());
                phase08RecordModel.OriginalSha256 = new string('0', 64); // tamper, tag unchanged
                phase08Envelope.RecordBase64 = Convert.ToBase64String(DataVanger.Shared.Quarantine.QuarantineRecordSerializer.SerializeRecord(phase08RecordModel));
                return DataVanger.Shared.Quarantine.QuarantineRecordSerializer.SerializeEnvelope(phase08Envelope);
            });
            var phase08IntegrityResult = phase08Service.VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08IntegrityResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.MetadataTampered && !phase08IntegrityResult.MetadataIntact,
                "Quarantine V2 detects metadata tampering.");
            var phase08RestoreResult = phase08Service.RestoreAsync(
                new DataVanger.Shared.Quarantine.QuarantineRestoreRequest { QuarantineId = phase08QuarantineResult.QuarantineId! }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08RestoreResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.MetadataTampered,
                "Quarantine V2 refuses restore when metadata is tampered.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 6. Restore recreates original bytes (filesystem store, atomic commit).
        {
            var phase08Root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dvq08_store_" + Guid.NewGuid().ToString("N"));
            var phase08Store = new DataVanger.Infrastructure.Quarantine.FileSystemQuarantineStore(phase08Root);
            var phase08Service = Phase08NewService(phase08Store, phase08Seed: "fs08", phase08Root: phase08Root);
            var phase08SourcePath = Phase08NewTempFile("phase08-restore-" + new string('x', 4096));
            var phase08OriginalBytes = System.IO.File.ReadAllBytes(phase08SourcePath);
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware, Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.ManualUserApproved },
                phase08CancellationToken).GetAwaiter().GetResult();
            var phase08DestPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dvq08_restored_" + Guid.NewGuid().ToString("N") + ".bin");
            var phase08RestoreResult = phase08Service.RestoreAsync(
                new DataVanger.Shared.Quarantine.QuarantineRestoreRequest { QuarantineId = phase08QuarantineResult.QuarantineId!, DestinationPath = phase08DestPath },
                phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08RestoreResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success
                   && System.IO.File.ReadAllBytes(phase08DestPath).SequenceEqual(phase08OriginalBytes),
                "Quarantine V2 restore recreates the original bytes after integrity verification.");
            System.IO.File.Delete(phase08SourcePath);
            System.IO.File.Delete(phase08DestPath);
            try { System.IO.Directory.Delete(phase08Root, true); } catch (Exception) { /* temp cleanup - ignore if already removed */ }
        }

        // 7. Restore refuses traversal paths.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-traversal");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            var phase08RestoreResult = phase08Service.RestoreAsync(
                new DataVanger.Shared.Quarantine.QuarantineRestoreRequest
                {
                    QuarantineId = phase08QuarantineResult.QuarantineId!,
                    DestinationPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), ".." + System.IO.Path.DirectorySeparatorChar + "dvq08_evil_" + Guid.NewGuid().ToString("N")),
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08RestoreResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.RestorePathInvalid,
                "Quarantine V2 restore refuses traversal ('..') paths.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 8. Restore refuses overwrite unless explicitly allowed.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-overwrite");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            var phase08DestPath = Phase08NewTempFile("phase08-existing-target");
            var phase08Deny = phase08Service.RestoreAsync(
                new DataVanger.Shared.Quarantine.QuarantineRestoreRequest { QuarantineId = phase08QuarantineResult.QuarantineId!, DestinationPath = phase08DestPath, AllowOverwrite = false },
                phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08Deny.Status == DataVanger.Shared.Quarantine.QuarantineStatus.RestoreTargetExists,
                "Quarantine V2 restore refuses to overwrite by default.");
            var phase08Allow = phase08Service.RestoreAsync(
                new DataVanger.Shared.Quarantine.QuarantineRestoreRequest { QuarantineId = phase08QuarantineResult.QuarantineId!, DestinationPath = phase08DestPath, AllowOverwrite = true },
                phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08Allow.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success
                   && System.IO.File.ReadAllText(phase08DestPath) == "phase08-overwrite",
                "Quarantine V2 restore overwrites only when explicitly allowed.");
            System.IO.File.Delete(phase08SourcePath);
            System.IO.File.Delete(phase08DestPath);
        }

        // 9. Missing payload reported safely.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-missing");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            phase08Store.RemovePayload(phase08QuarantineResult.Record!.PayloadName);
            var phase08IntegrityResult = phase08Service.VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08IntegrityResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.PayloadMissing
                   && phase08IntegrityResult.RecordState == DataVanger.Shared.Quarantine.QuarantineRecordState.MissingPayload,
                "Quarantine V2 reports a missing payload safely.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 10. Corrupt (undecodable) payload reported safely.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-corrupt");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            phase08Store.TamperPayloadRaw(phase08QuarantineResult.Record!.PayloadName, _ => new byte[] { 9, 9, 9 });
            var phase08IntegrityResult = phase08Service.VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08IntegrityResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.IntegrityCheckFailed
                   && phase08IntegrityResult.RecordState == DataVanger.Shared.Quarantine.QuarantineRecordState.Corrupt,
                "Quarantine V2 reports a corrupt payload safely.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 11. Original delete failure reported without crashing.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store,
                phase08Options: DataVanger.Shared.Quarantine.QuarantineOptions.Production(),
                phase08Remover: _ => throw new System.IO.IOException("phase08 simulated denied delete"));
            var phase08SourcePath = Phase08NewTempFile("phase08-deletefail");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08SourcePath,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.Automatic,
                    DeleteOriginalAfterStore = true,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.OriginalDeleteFailed
                   && phase08QuarantineResult.OriginalDeleteFailed
                   && System.IO.File.Exists(phase08SourcePath),
                "Quarantine V2 reports original-delete failure without crashing and retains the original.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 12. Cancellation respected.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            var phase08SourcePath = Phase08NewTempFile("phase08-cancel");
            using var phase08Cts = new System.Threading.CancellationTokenSource();
            phase08Cts.Cancel();
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08Cts.Token).GetAwaiter().GetResult();
            assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Cancelled,
                "Quarantine V2 respects cancellation.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 13. Development mode never deletes the original (build/test safety).
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store, phase08Options: DataVanger.Shared.Quarantine.QuarantineOptions.DevelopmentSafe());
            var phase08SourcePath = Phase08NewTempFile("phase08-devsafe");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08SourcePath,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.Automatic,
                    DeleteOriginalAfterStore = true,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success
                   && System.IO.File.Exists(phase08SourcePath),
                "Quarantine V2 development mode never deletes the original.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 14. Deterministic in-memory key protector; different seed cannot authenticate.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08ServiceA = Phase08NewService(phase08Store, phase08Seed: "phase08-shared");
            var phase08SourcePath = Phase08NewTempFile("phase08-deterministic");
            var phase08QuarantineResult = phase08ServiceA.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest { SourcePath = phase08SourcePath, Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk },
                phase08CancellationToken).GetAwaiter().GetResult();
            var phase08SameSeedIntegrityResult = Phase08NewService(phase08Store, phase08Seed: "phase08-shared")
                .VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08SameSeedIntegrityResult.IsIntact,
                "Quarantine V2 in-memory key protector is deterministic for the same seed.");
            var phase08DiffSeedIntegrityResult = Phase08NewService(phase08Store, phase08Seed: "phase08-other")
                .VerifyAsync(phase08QuarantineResult.QuarantineId!, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08DiffSeedIntegrityResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.MetadataTampered,
                "Quarantine V2 different-seed protector cannot authenticate metadata.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 15. Unsupported DPAPI/platform degrades gracefully (no crash).
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Dpapi = new DataVanger.Infrastructure.Quarantine.DpapiQuarantineKeyProtector(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dvq08_keys_" + Guid.NewGuid().ToString("N")));
            var phase08Service = new DataVanger.Engine.Quarantine.QuarantineService(
                phase08Store, new DataVanger.Engine.Quarantine.QuarantineCryptoProvider(), phase08Dpapi,
                DataVanger.Shared.Quarantine.QuarantineOptions.DevelopmentSafe());
            var phase08SourcePath = Phase08NewTempFile("phase08-dpapi");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08SourcePath,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.ManualUserApproved,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            if (OperatingSystem.IsWindows())
                assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success,
                    "Quarantine V2 DPAPI key protection works on Windows.");
            else
                assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.UnsupportedPlatform,
                    "Quarantine V2 degrades gracefully when DPAPI is unsupported.");
            System.IO.File.Delete(phase08SourcePath);
        }

        // 16/17. Automatic quarantine is ConfirmedMalware-only; heuristic-only never auto-quarantines.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            var phase08Service = Phase08NewService(phase08Store);
            foreach (var phase08Classification in new[]
                     {
                         DataVanger.Shared.Quarantine.QuarantineThreatClassification.Suspect,
                         DataVanger.Shared.Quarantine.QuarantineThreatClassification.HighRisk,
                     })
            {
                var phase08SourcePath = Phase08NewTempFile("phase08-auto-" + phase08Classification);
                var phase08AutoResult = phase08Service.QuarantineAsync(
                    new DataVanger.Shared.Quarantine.QuarantineRequest
                    {
                        SourcePath = phase08SourcePath,
                        Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.Automatic,
                        Classification = phase08Classification,
                    }, phase08CancellationToken).GetAwaiter().GetResult();
                assert(phase08AutoResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.PolicyDenied,
                    "Quarantine V2 denies automatic quarantine for non-confirmed classification (" + phase08Classification + ").");
                System.IO.File.Delete(phase08SourcePath);
            }
            var phase08ConfirmedSource = Phase08NewTempFile("phase08-auto-confirmed");
            var phase08ConfirmedResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08ConfirmedSource,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.Automatic,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08ConfirmedResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success,
                "Quarantine V2 allows automatic quarantine only for ConfirmedMalware.");
            System.IO.File.Delete(phase08ConfirmedSource);
        }

        // 18/19. Runtime events are telemetry (never a verdict) + report-safe metadata without secrets.
        {
            var phase08Store = new DataVanger.Engine.Quarantine.InMemoryQuarantineStore();
            using var phase08Pipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
            var phase08Consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
            phase08Pipeline.Subscribe(phase08Consumer);
            var phase08Sink = new DataVanger.Engine.Quarantine.RuntimeEventQuarantineAuditSink(phase08Pipeline);
            var phase08Service = Phase08NewService(phase08Store, phase08Sink: phase08Sink);
            var phase08SourcePath = Phase08NewTempFile("PHASE08-RUNTIME-SECRET");
            var phase08QuarantineResult = phase08Service.QuarantineAsync(
                new DataVanger.Shared.Quarantine.QuarantineRequest
                {
                    SourcePath = phase08SourcePath,
                    Classification = DataVanger.Shared.Quarantine.QuarantineThreatClassification.ConfirmedMalware,
                    Origin = DataVanger.Shared.Quarantine.QuarantineRequestOrigin.Automatic,
                }, phase08CancellationToken).GetAwaiter().GetResult();
            assert(phase08QuarantineResult.Status == DataVanger.Shared.Quarantine.QuarantineStatus.Success,
                "Quarantine V2 stores with a runtime audit sink attached.");
            var phase08RuntimeEvents = phase08Consumer.Snapshot();
            assert(phase08RuntimeEvents.Count > 0
                   && phase08RuntimeEvents.All(e => e.Source == DataVanger.Shared.RuntimeEvents.RuntimeEventSource.Quarantine
                                                    && e.Category == DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.QuarantineAction
                                                    && e.Severity <= DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.High
                                                    && e.SubjectPath == null),
                "Quarantine V2 runtime events are Quarantine telemetry that never escalate to a verdict or leak the original path.");
            var phase08LeakFound = false;
            foreach (var phase08RuntimeEvent in phase08RuntimeEvents)
                foreach (var phase08Pair in phase08RuntimeEvent.Metadata)
                    if (phase08Pair.Value.Contains("PHASE08-RUNTIME-SECRET")) phase08LeakFound = true;
            assert(!phase08LeakFound
                   && phase08RuntimeEvents.Any(e => e.Metadata.ContainsKey("quarantineId") && e.Metadata.ContainsKey("originalSha256")),
                "Quarantine V2 reporting metadata includes id + SHA-256 but never decrypted content or secrets.");
            System.IO.File.Delete(phase08SourcePath);
        }
    }
}

// ── Phase 2 / Step 10: Signed Updates and Trusted Signature Feed Delivery ────
// Self-contained, deterministic test section. Wrapped in a uniquely-named
// file-local helper so it introduces NO top-level locals (avoids duplicate-
// local regressions). Everything is in-memory / temp-only: no network, no
// admin, no background loops, no update package code execution. All locals use
// the phase10 prefix. Crypto is RSA-PSS SHA-256 via System.Security.Cryptography
// with a hardcoded TEST-ONLY key fixture (never generated at runtime).
// Decomposed (phase 09): invoked as a dedicated [Fact] by UpdateTests. Promoted
// from file-local to internal so the per-subsystem test class can call Run(...).
internal static class Phase10SignedUpdates
{
    // TEST-ONLY KEY — never use in production. Deterministic PKCS#8 RSA-2048
    // private key embedded as a constant so signature tests are reproducible
    // (RSA.Create() is NOT called to generate a random key at test runtime).
    private const string Phase10RsaPrivateKeyPem =
        "-----BEGIN PRIVATE KEY-----\n" +
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDcWVWB9obPtPeF\n" +
        "/Ifgj0iG7Gq4OBAqINSzTyWjF2pi2/pK2Z3jXZfnGkc1u8/HUKzvXtK/7y8iRk0X\n" +
        "iNZb6AEKRtqsq1HwMscLQStszyRqiwelm+oqdABf2HlQ0GBhlWiRs2nVqVw/liIT\n" +
        "rxXYlM00tZID9eJoQWTU8Z7vMkCDax6VU28lKH8PwoiivDbR/0o0mQ2MkC1exold\n" +
        "si9XC1AE+FhiaQCm7sSjpZb+Slb8fEwdQe4svNPxCi9/YEs3KRyA+BxxN2NmBHi/\n" +
        "YFyLqKcK/bxKpkj3iCco/I4JTKVa1pgnFn8XOVb08L3ZRBtIv2Rs+chsJ14Km9/N\n" +
        "bjcBJ3sHAgMBAAECggEASWijoZAJeqI+Ak/OzsO9dGHH7gaTcA2O/wvDrLFs2nGR\n" +
        "0aTtQmWYaUAqcB7ZSnw4mOicyp+7Mq58GXaXf3fr/Mn9KSBMRHsOL9QuzOm3pp0Z\n" +
        "15T5btpFk6jRRdid+3SkqUG95RYuqupwAOHII+by9Hf3JMWif3wlxQGYIvU5Y+5K\n" +
        "IzY+E5QrnWe84wt+5ptfu7NfhbY1B3UAvusG0AGU9orlYS7U8sMTSG24w+pDtW98\n" +
        "shzHo1DVGByI9fphuFuyZ5O6dCO9RIKEDnj4pkg6tsyHpQypJFuinNyVh9NACldJ\n" +
        "c1u9XzD646PZwP/pXA6CKvY/EQl+zQNkrJ/VgIFhvQKBgQD1n4ql8+vugRuBC8GC\n" +
        "bnTBoM70GaBLHgZNbZFdt64bJ4RfAjN+KcQ+aNTxFQlB+UIC4Bm8Gos2ugmvSVUD\n" +
        "Wv5n2/DmfREbQvh2GqtWZAPrq6hBQzI5aCmzajflYUPfeEUGzUAgUsatslmy7PU4\n" +
        "j1ZcYa9AqFTPUg64dENZ2OrAZQKBgQDlqHJr2dQ0ARdXSa7Wh/fCtCBDuougIJat\n" +
        "kR9TuU6e70nexUhkNq+uD1OafUKEVxDTGHmunq2vMKm79kpphR1iAj89IYp/T/Nj\n" +
        "B5unxUt1AP2qhU0YlRBpAsoAOHL1A1ShBpNAxP6ub3KLLgsBO7x/8gHIF2R18JbX\n" +
        "oQ9O9P/4+wKBgB3LorgK5N3jz4BR+sFlwMgUR8aYrTcvhzgxSGcD9xzYKFiWHcT6\n" +
        "MBIaCWrNUHguUnGi2bxVw/l5i981mBh2G1Jh/dEX7tFNyHIbPhmWvFsEUb7I9fi8\n" +
        "yAI5qloq+F7NaiIvF85T/EHp1rO7xut7h9BhES9YvCECJUL+54SoqaF5AoGAPfga\n" +
        "B+gbTn0M40zKlLDTtgIMwrnPe0HP5r3GCj1ybYh8ElSBmCj5dqpEEOfDzxn/PDba\n" +
        "frfqfd9PrZxjr91vdEbO8ZvfV0MnlY0z/y1JkyTVTfHyP7PZXbyW7UBOJLblWx3/\n" +
        "FfcSEdeYvN2LsqV/07ZlrKxDO1/UFBMtokyR1YkCgYAyWRBSRRRoGnu7QxALcbwT\n" +
        "52nZnCLJdvR5aGj8KitySlvfm6mu9lDvz+NBAqrfAr182YOz8UIQ8qNDg3Dl6a+1\n" +
        "2wlO04WkQGHXEO4cXvZuLXgLXOxMtvPHGiGGjZs/b+RMpCysZ1MdQ+Mb4L4rTOlZ\n" +
        "A7ZQ2TwcCTsdn8Zu/qlZAg==\n" +
        "-----END PRIVATE KEY-----\n";

    // TEST-ONLY KEY — never use in production. Matching SubjectPublicKeyInfo.
    private const string Phase10RsaPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3FlVgfaGz7T3hfyH4I9I\n" +
        "huxquDgQKiDUs08loxdqYtv6Stmd412X5xpHNbvPx1Cs717Sv+8vIkZNF4jWW+gB\n" +
        "CkbarKtR8DLHC0ErbM8kaosHpZvqKnQAX9h5UNBgYZVokbNp1alcP5YiE68V2JTN\n" +
        "NLWSA/XiaEFk1PGe7zJAg2selVNvJSh/D8KIorw20f9KNJkNjJAtXsaJXbIvVwtQ\n" +
        "BPhYYmkApu7Eo6WW/kpW/HxMHUHuLLzT8Qovf2BLNykcgPgccTdjZgR4v2Bci6in\n" +
        "Cv28SqZI94gnKPyOCUylWtaYJxZ/FzlW9PC92UQbSL9kbPnIbCdeCpvfzW43ASd7\n" +
        "BwIDAQAB\n" +
        "-----END PUBLIC KEY-----\n";

    private const string Phase10RsaKeyId = "phase10-test-rsa-key-1";
    private const string Phase10FeedId = "datavanger-default-feed";

    private static DataVanger.Shared.Updates.UpdatePolicy Phase10TestPolicy()
        => new() { Mode = DataVanger.Shared.Updates.UpdateMode.Test, FeedId = Phase10FeedId };

    private static DataVanger.Shared.Updates.UpdateManifest Phase10BaseManifest(long phase10Sequence, string phase10Sha256 = "abc123")
        => new()
        {
            SchemaVersion = 1,
            FeedId = Phase10FeedId,
            Sequence = phase10Sequence,
            PublishedUtc = "2026-01-01T00:00:00Z",
            MinimumSupportedClientVersion = "0.0.0",
            Packages = new[]
            {
                new DataVanger.Shared.Updates.UpdatePackageEntry
                {
                    Id = "hash-blacklist",
                    Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist,
                    Version = "2026.01.01.1",
                    Sha256 = phase10Sha256,
                    SizeBytes = 12345,
                    RelativePath = "feeds/hash-blacklist.json",
                    Required = true,
                },
            },
        };

    private static DataVanger.Engine.Updates.SignedUpdates.SignedManifestVerifier Phase10NewVerifier()
        => new(new[]
        {
            new DataVanger.Shared.Updates.PinnedPublicKey(
                Phase10RsaKeyId,
                DataVanger.Engine.Updates.SignedUpdates.SignedManifestVerifier.AlgorithmRsaPss,
                Phase10RsaPublicKeyPem),
        });

    private static DataVanger.Shared.Updates.UpdateManifest Phase10Sign(DataVanger.Shared.Updates.UpdateManifest phase10Manifest)
        => DataVanger.Engine.Updates.SignedUpdates.UpdateManifestSigner.Sign(
            phase10Manifest,
            Phase10RsaPrivateKeyPem,
            DataVanger.Engine.Updates.SignedUpdates.SignedManifestVerifier.AlgorithmRsaPss,
            Phase10RsaKeyId);

    // Builds a self-consistent signed manifest whose single package entry matches
    // the supplied content (correct sha + size) plus an in-memory transport.
    private static DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateTransport Phase10BuildTransport(
        long phase10Sequence, byte[] phase10Content, string phase10RelativePath = "feeds/hash-blacklist.json",
        DataVanger.Shared.Updates.UpdatePackageKind phase10Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist,
        bool phase10Required = true, long phase10DeclaredSize = -1)
    {
        var phase10Sha = DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.ComputeSha256Hex(phase10Content);
        var phase10Manifest = new DataVanger.Shared.Updates.UpdateManifest
        {
            SchemaVersion = 1,
            FeedId = Phase10FeedId,
            Sequence = phase10Sequence,
            PublishedUtc = "2026-01-01T00:00:00Z",
            MinimumSupportedClientVersion = "0.0.0",
            Packages = new[]
            {
                new DataVanger.Shared.Updates.UpdatePackageEntry
                {
                    Id = "hash-blacklist",
                    Kind = phase10Kind,
                    Version = "2026.01.01." + phase10Sequence,
                    Sha256 = phase10Sha,
                    SizeBytes = phase10DeclaredSize < 0 ? phase10Content.LongLength : phase10DeclaredSize,
                    RelativePath = phase10RelativePath,
                    Required = phase10Required,
                },
            },
        };
        phase10Manifest = Phase10Sign(phase10Manifest);
        var phase10ManifestBytes = DataVanger.Engine.Updates.SignedUpdates.UpdateManifestJson.Serialize(phase10Manifest);
        return new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateTransport(
            phase10ManifestBytes,
            new System.Collections.Generic.Dictionary<string, byte[]> { [phase10RelativePath] = phase10Content });
    }

    private static DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService Phase10NewService(
        DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore phase10State, long phase10Sequence, byte[] phase10Content)
        => Phase10NewServiceForFeed(phase10State, Phase10BuildTransport(phase10Sequence, phase10Content));

    private static DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService Phase10NewServiceForFeed(
        DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore phase10State,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateTransport phase10Transport)
        => new(Phase10TestPolicy(), Phase10NewVerifier(), new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier(),
            phase10State, new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink(), phase10Transport);

    private static DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService Phase10NewServiceFull(
        DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore phase10State,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateContentSink phase10Sink,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateTransport phase10Transport)
        => new(Phase10TestPolicy(), Phase10NewVerifier(), new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier(),
            phase10State, phase10Sink, phase10Transport);

    private static DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService Phase10NewServiceWithEvents(
        DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore phase10State,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateContentSink phase10Sink,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateTransport phase10Transport,
        DataVanger.Shared.RuntimeEvents.IRuntimeEventPublisher phase10Publisher)
        => new(Phase10TestPolicy(), Phase10NewVerifier(), new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier(),
            phase10State, phase10Sink, phase10Transport, phase10Publisher);

    private static DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService Phase10NewServiceWithPolicy(
        DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore phase10State,
        DataVanger.Shared.Updates.UpdatePolicy phase10Policy,
        DataVanger.Engine.Updates.SignedUpdates.IUpdateTransport phase10Transport)
        => new(phase10Policy, Phase10NewVerifier(), new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier(),
            phase10State, new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink(), phase10Transport);

    private sealed class Phase10FailingContentSink : DataVanger.Engine.Updates.SignedUpdates.IUpdateContentSink
    {
        public void Stage(string feedId, long sequence, string canonicalManifestSha256,
            System.Collections.Generic.IReadOnlyList<DataVanger.Engine.Updates.SignedUpdates.StagedPackage> packages) { }
        public void Commit(string feedId, long sequence) => throw new System.IO.IOException("synthetic staging failure");
        public void Restore(string feedId) { }
    }

    public static void Run(System.Action<bool, string> assert)
    {
        // 1. Canonical payload deterministic hardcoded output.
        {
            var phase10Manifest = Phase10BaseManifest(42);
            const string phase10ExpectedCanonical =
                "DATAVANGER-UPDATE-CANONICAL-V1\n" +
                "schemaVersion=1\n" +
                "feedId=datavanger-default-feed\n" +
                "sequence=42\n" +
                "publishedUtc=2026-01-01T00:00:00Z\n" +
                "minimumSupportedClientVersion=0.0.0\n" +
                "packages=1\n" +
                "package=hash-blacklist|HashBlacklist|2026.01.01.1|abc123|12345|feeds/hash-blacklist.json|true\n";
            var phase10CanonicalString = DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.BuildString(phase10Manifest);
            assert(phase10CanonicalString == phase10ExpectedCanonical,
                "Phase10 canonical payload must match the hardcoded expected output.");
            var phase10CanonicalBytes = DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.Build(phase10Manifest);
            assert(phase10CanonicalBytes.SequenceEqual(System.Text.Encoding.UTF8.GetBytes(phase10ExpectedCanonical)),
                "Phase10 canonical payload bytes must be UTF-8 of the expected string.");
            assert(DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.BuildString(Phase10BaseManifest(42)) == phase10CanonicalString,
                "Phase10 canonical payload must be deterministic across repeated calls.");
            assert(DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.ComputeCanonicalSha256(phase10Manifest)
                   == "1d5faa2352871632b772e8349788871aab45088984abcc409b5e2e3177c0dc67",
                "Phase10 canonical SHA-256 must match the hardcoded expected digest.");
        }

        // 2. Canonical payload changes when sequence changes.
        {
            var phase10CanonicalBytes = DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.BuildString(Phase10BaseManifest(42));
            var phase10CanonicalBytesNext = DataVanger.Engine.Updates.SignedUpdates.UpdateCanonicalPayloadBuilder.BuildString(Phase10BaseManifest(43));
            assert(phase10CanonicalBytes != phase10CanonicalBytesNext,
                "Phase10 canonical payload must change when the sequence changes.");
        }

        // 3. Valid signed manifest accepted.
        {
            var phase10Verifier = Phase10NewVerifier();
            var phase10VerificationResult = phase10Verifier.Verify(Phase10Sign(Phase10BaseManifest(10)));
            assert(phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.Accepted,
                "Phase10 valid signed manifest must be accepted.");
        }

        // 4. Unsigned manifest rejected.
        {
            var phase10VerificationResult = Phase10NewVerifier().Verify(Phase10BaseManifest(10));
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.ManifestUnsigned,
                "Phase10 unsigned manifest must be rejected.");
        }

        // 5. Invalid signature rejected.
        {
            var phase10Signed = Phase10Sign(Phase10BaseManifest(10));
            var phase10Tampered = new DataVanger.Shared.Updates.UpdateManifest
            {
                SchemaVersion = phase10Signed.SchemaVersion, FeedId = phase10Signed.FeedId, Sequence = phase10Signed.Sequence,
                PublishedUtc = phase10Signed.PublishedUtc, MinimumSupportedClientVersion = phase10Signed.MinimumSupportedClientVersion,
                Packages = phase10Signed.Packages,
                Signature = new DataVanger.Shared.Updates.UpdateManifestSignature
                {
                    Algorithm = phase10Signed.Signature!.Algorithm, KeyId = phase10Signed.Signature.KeyId,
                    Value = System.Convert.ToBase64String(new byte[256]),
                },
            };
            var phase10VerificationResult = Phase10NewVerifier().Verify(phase10Tampered);
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.SignatureInvalid,
                "Phase10 invalid signature must be rejected.");
        }

        // 6. Unknown key rejected.
        {
            var phase10Signed = DataVanger.Engine.Updates.SignedUpdates.UpdateManifestSigner.Sign(
                Phase10BaseManifest(10), Phase10RsaPrivateKeyPem,
                DataVanger.Engine.Updates.SignedUpdates.SignedManifestVerifier.AlgorithmRsaPss, "phase10-unknown-key");
            var phase10VerificationResult = Phase10NewVerifier().Verify(phase10Signed);
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.UnknownKey,
                "Phase10 unknown key id must be rejected.");
        }

        // 7. Unsupported algorithm rejected.
        {
            var phase10Signed = Phase10Sign(Phase10BaseManifest(10));
            var phase10BadAlgo = new DataVanger.Shared.Updates.UpdateManifest
            {
                SchemaVersion = phase10Signed.SchemaVersion, FeedId = phase10Signed.FeedId, Sequence = phase10Signed.Sequence,
                PublishedUtc = phase10Signed.PublishedUtc, MinimumSupportedClientVersion = phase10Signed.MinimumSupportedClientVersion,
                Packages = phase10Signed.Packages,
                Signature = new DataVanger.Shared.Updates.UpdateManifestSignature
                {
                    Algorithm = "Ed25519", KeyId = phase10Signed.Signature!.KeyId, Value = phase10Signed.Signature.Value,
                },
            };
            var phase10VerificationResult = Phase10NewVerifier().Verify(phase10BadAlgo);
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.UnsupportedAlgorithm,
                "Phase10 unsupported algorithm must be rejected.");
        }

        // 8. Tampered manifest rejected (field mutated after signing).
        {
            var phase10Signed = Phase10Sign(Phase10BaseManifest(10));
            var phase10Mutated = new DataVanger.Shared.Updates.UpdateManifest
            {
                SchemaVersion = phase10Signed.SchemaVersion, FeedId = phase10Signed.FeedId, Sequence = 9999,
                PublishedUtc = phase10Signed.PublishedUtc, MinimumSupportedClientVersion = phase10Signed.MinimumSupportedClientVersion,
                Packages = phase10Signed.Packages, Signature = phase10Signed.Signature,
            };
            var phase10VerificationResult = Phase10NewVerifier().Verify(phase10Mutated);
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.SignatureInvalid,
                "Phase10 tampered manifest must be rejected.");
        }

        // 9. Malformed manifest rejected safely (no throw).
        {
            var phase10VerificationResult = Phase10NewVerifier().Verify(new DataVanger.Shared.Updates.UpdateManifest { FeedId = "", Sequence = 1 });
            assert(!phase10VerificationResult.IsValid
                   && phase10VerificationResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.ManifestMalformed,
                "Phase10 malformed manifest must be rejected safely.");
            assert(!DataVanger.Engine.Updates.SignedUpdates.UpdateManifestJson.TryDeserialize(
                       System.Text.Encoding.UTF8.GetBytes("{ this is not json"), out _),
                "Phase10 malformed JSON must fail deserialization without throwing.");
        }

        // 10. Correct package SHA-256 accepted.
        {
            var phase10Content = System.Text.Encoding.UTF8.GetBytes("{\"hashes\":[]}");
            var phase10Entry = new DataVanger.Shared.Updates.UpdatePackageEntry
            {
                Id = "p", Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist, RelativePath = "feeds/p.json",
                Sha256 = DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.ComputeSha256Hex(phase10Content),
                SizeBytes = phase10Content.Length,
            };
            assert(new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier().Validate(phase10Entry, phase10Content, Phase10TestPolicy()).IsValid,
                "Phase10 correct package SHA-256 must be accepted.");
        }

        // 11. Incorrect package SHA-256 rejected.
        {
            var phase10Content = System.Text.Encoding.UTF8.GetBytes("{\"hashes\":[]}");
            var phase10Entry = new DataVanger.Shared.Updates.UpdatePackageEntry
            {
                Id = "p", Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist, RelativePath = "feeds/p.json",
                Sha256 = "deadbeef", SizeBytes = phase10Content.Length,
            };
            var phase10PackageResult = new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier().Validate(phase10Entry, phase10Content, Phase10TestPolicy());
            assert(!phase10PackageResult.IsValid
                   && phase10PackageResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.PackageHashMismatch,
                "Phase10 incorrect package SHA-256 must be rejected.");
        }

        // 12. Oversized package rejected.
        {
            var phase10Content = new byte[64];
            var phase10Entry = new DataVanger.Shared.Updates.UpdatePackageEntry
            {
                Id = "p", Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist, RelativePath = "feeds/p.json",
                Sha256 = DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.ComputeSha256Hex(phase10Content),
                SizeBytes = phase10Content.Length,
            };
            var phase10Policy = new DataVanger.Shared.Updates.UpdatePolicy { Mode = DataVanger.Shared.Updates.UpdateMode.Test, MaxPackageSizeBytes = 16 };
            var phase10PackageResult = new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier().Validate(phase10Entry, phase10Content, phase10Policy);
            assert(!phase10PackageResult.IsValid
                   && phase10PackageResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.PackageOversized,
                "Phase10 oversized package must be rejected.");
        }

        // 13. Relative path traversal rejected.
        {
            var phase10Content = new byte[8];
            var phase10Entry = new DataVanger.Shared.Updates.UpdatePackageEntry
            {
                Id = "p", Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist, RelativePath = "../escape.json",
                Sha256 = DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.ComputeSha256Hex(phase10Content),
                SizeBytes = phase10Content.Length,
            };
            var phase10PackageResult = new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier().Validate(phase10Entry, phase10Content, Phase10TestPolicy());
            assert(!phase10PackageResult.IsValid
                   && phase10PackageResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.PackagePathRejected,
                "Phase10 relative path traversal must be rejected.");
            assert(!DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.IsSafeRelativePath("a/../../b")
                   && !DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.IsSafeRelativePath("..\\b"),
                "Phase10 path safety helper must reject traversal.");
        }

        // 14. Absolute package path rejected.
        {
            var phase10Content = new byte[8];
            assert(!DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.IsSafeRelativePath("/etc/passwd")
                   && !DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.IsSafeRelativePath("C:\\windows\\x")
                   && !DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.IsSafeRelativePath("\\\\server\\share\\x"),
                "Phase10 absolute/drive/UNC paths must be rejected by the helper.");
            var phase10Entry = new DataVanger.Shared.Updates.UpdatePackageEntry
            {
                Id = "p", Kind = DataVanger.Shared.Updates.UpdatePackageKind.HashBlacklist, RelativePath = "/etc/passwd",
                Sha256 = DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier.ComputeSha256Hex(phase10Content),
                SizeBytes = phase10Content.Length,
            };
            var phase10PackageResult = new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier().Validate(phase10Entry, phase10Content, Phase10TestPolicy());
            assert(!phase10PackageResult.IsValid
                   && phase10PackageResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.PackagePathRejected,
                "Phase10 absolute package path must be rejected.");
        }

        // 15. Lower sequence rejected (anti-downgrade).
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10ApplyResultHigh = Phase10NewService(phase10State, 50, System.Text.Encoding.UTF8.GetBytes("v50")).CheckAndApply();
            assert(phase10ApplyResultHigh.Succeeded && phase10ApplyResultHigh.Kind == DataVanger.Shared.Updates.UpdateResultKind.Applied,
                "Phase10 baseline higher sequence must apply.");
            var phase10ApplyResult = Phase10NewService(phase10State, 49, System.Text.Encoding.UTF8.GetBytes("v49")).CheckAndApply();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.DowngradeRejected,
                "Phase10 lower sequence must be rejected.");
            assert(phase10State.GetCurrent(Phase10FeedId).HighestSequence == 50,
                "Phase10 downgrade attempt must not alter stored state.");
        }

        // 16. Equal sequence with different canonical hash rejected.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            Phase10NewService(phase10State, 50, System.Text.Encoding.UTF8.GetBytes("content-A")).CheckAndApply();
            var phase10ApplyResult = Phase10NewService(phase10State, 50, System.Text.Encoding.UTF8.GetBytes("content-B-different")).CheckAndApply();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.SequenceConflict,
                "Phase10 equal sequence with different canonical hash must be rejected.");
        }

        // 17. Equal sequence with identical canonical hash accepted idempotently.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10Transport = Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("same-content"));
            Phase10NewServiceForFeed(phase10State, phase10Transport).CheckAndApply();
            var phase10ApplyResult = Phase10NewServiceForFeed(phase10State, phase10Transport).CheckAndApply();
            assert(phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.AlreadyCurrent,
                "Phase10 equal sequence with identical canonical hash must be idempotently accepted.");
        }

        // 18. Higher sequence accepted and state updated.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            Phase10NewService(phase10State, 50, System.Text.Encoding.UTF8.GetBytes("v50")).CheckAndApply();
            var phase10ApplyResult = Phase10NewService(phase10State, 51, System.Text.Encoding.UTF8.GetBytes("v51")).CheckAndApply();
            assert(phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.Applied
                   && phase10State.GetCurrent(Phase10FeedId).HighestSequence == 51,
                "Phase10 higher sequence must apply and update stored state.");
        }

        // 19. Staging failure preserves previous active state.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10Sink = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink();
            Phase10NewServiceFull(phase10State, phase10Sink, Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50"))).CheckAndApply();
            var phase10ApplyResult = Phase10NewServiceFull(phase10State, new Phase10FailingContentSink(),
                Phase10BuildTransport(51, System.Text.Encoding.UTF8.GetBytes("v51"))).CheckAndApply();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.StagingFailed,
                "Phase10 staging failure must return StagingFailed.");
            assert(phase10State.GetCurrent(Phase10FeedId).HighestSequence == 50,
                "Phase10 staging failure must preserve the previous active state.");
        }

        // 20. Rollback restores last-known-good state.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10Sink = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink();
            Phase10NewServiceFull(phase10State, phase10Sink, Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50"))).CheckAndApply();
            Phase10NewServiceFull(phase10State, phase10Sink, Phase10BuildTransport(51, System.Text.Encoding.UTF8.GetBytes("v51"))).CheckAndApply();
            var phase10ApplyResult = Phase10NewServiceFull(phase10State, phase10Sink,
                Phase10BuildTransport(51, System.Text.Encoding.UTF8.GetBytes("v51"))).Rollback();
            assert(phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.RollbackCompleted
                   && phase10State.GetCurrent(Phase10FeedId).HighestSequence == 50,
                "Phase10 rollback must restore the last-known-good state.");
        }

        // 21. Rollback unavailable returns structured result.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10ApplyResult = Phase10NewService(phase10State, 50, System.Text.Encoding.UTF8.GetBytes("v50")).Rollback();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.NoRollbackAvailable,
                "Phase10 rollback without a snapshot must return NoRollbackAvailable.");
        }

        // 22. Update failure returns a structured result, not an unhandled exception.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10ApplyResult = Phase10NewServiceForFeed(phase10State,
                new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateTransport(null)).CheckAndApply();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.TransportUnavailable,
                "Phase10 missing manifest must return a structured failure.");
            var phase10MalformedResult = Phase10NewServiceForFeed(phase10State,
                new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateTransport(System.Text.Encoding.UTF8.GetBytes("not-json"))).CheckAndApply();
            assert(!phase10MalformedResult.Succeeded && phase10MalformedResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.ManifestMalformed,
                "Phase10 malformed manifest must return a structured failure, never an unhandled exception.");
        }

        // 23. Update telemetry never becomes ConfirmedMalware.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            using var phase10Pipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
            var phase10Consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
            phase10Pipeline.Subscribe(phase10Consumer);
            var phase10ApplyResult = Phase10NewServiceWithEvents(phase10State,
                new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink(),
                Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50")), phase10Pipeline).CheckAndApply();
            var phase10Events = phase10Consumer.Snapshot();
            assert(phase10Events.Count > 0
                   && phase10Events.All(e => e.Source == DataVanger.Shared.RuntimeEvents.RuntimeEventSource.UpdateManager
                                             && e.Category == DataVanger.Shared.RuntimeEvents.RuntimeEventCategory.UpdateAction
                                             && e.Severity <= DataVanger.Shared.RuntimeEvents.RuntimeEventSeverity.High),
                "Phase10 update telemetry must be UpdateManager/UpdateAction and never escalate to a verdict.");
            assert(!phase10ApplyResult.IsConfirmedMalware,
                "Phase10 apply result must never be ConfirmedMalware.");
        }

        // 24. Disabled mode emits no update activity.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            using var phase10Pipeline = new DataVanger.Engine.RuntimeEvents.InMemoryRuntimeEventPipeline();
            var phase10Consumer = new DataVanger.Engine.RuntimeEvents.CollectingRuntimeEventConsumer();
            phase10Pipeline.Subscribe(phase10Consumer);
            var phase10Policy = new DataVanger.Shared.Updates.UpdatePolicy { Mode = DataVanger.Shared.Updates.UpdateMode.Disabled, FeedId = Phase10FeedId };
            var phase10Service = new DataVanger.Engine.Updates.SignedUpdates.SignedUpdateService(
                phase10Policy, Phase10NewVerifier(), new DataVanger.Engine.Updates.SignedUpdates.UpdatePackageVerifier(),
                phase10State, new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateContentSink(),
                Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50")), phase10Pipeline);
            var phase10ApplyResult = phase10Service.CheckAndApply();
            assert(phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.Disabled && phase10Consumer.Count == 0,
                "Phase10 Disabled mode must emit no update activity.");
        }

        // 25. Test mode uses hardcoded test key and in-memory transport (end-to-end).
        {
            var phase10ApplyResult = Phase10NewService(new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore(),
                7, System.Text.Encoding.UTF8.GetBytes("test-mode")).CheckAndApply();
            assert(phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.Applied,
                "Phase10 Test mode must apply using the hardcoded key and in-memory transport.");
        }

        // 26. Downgrade override disabled by default (even in Development mode).
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            Phase10NewServiceWithPolicy(phase10State,
                new DataVanger.Shared.Updates.UpdatePolicy { Mode = DataVanger.Shared.Updates.UpdateMode.Development, FeedId = Phase10FeedId },
                Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50"))).CheckAndApply();
            var phase10ApplyResult = Phase10NewServiceWithPolicy(phase10State,
                new DataVanger.Shared.Updates.UpdatePolicy { Mode = DataVanger.Shared.Updates.UpdateMode.Development, FeedId = Phase10FeedId },
                Phase10BuildTransport(49, System.Text.Encoding.UTF8.GetBytes("v49"))).CheckAndApply();
            assert(!phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.DowngradeRejected,
                "Phase10 downgrade override must be disabled by default even in Development mode.");
        }

        // 27. Downgrade override allowed only in Development/Test when explicitly enabled.
        {
            var phase10State = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10Policy = new DataVanger.Shared.Updates.UpdatePolicy
            {
                Mode = DataVanger.Shared.Updates.UpdateMode.Development, FeedId = Phase10FeedId, AllowDowngradeInDevelopmentMode = true,
            };
            Phase10NewServiceWithPolicy(phase10State, phase10Policy, Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50"))).CheckAndApply();
            var phase10ApplyResult = Phase10NewServiceWithPolicy(phase10State, phase10Policy,
                Phase10BuildTransport(49, System.Text.Encoding.UTF8.GetBytes("v49"))).CheckAndApply();
            assert(phase10ApplyResult.Succeeded && phase10ApplyResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.Applied,
                "Phase10 downgrade override must be allowed in Development mode when explicitly enabled.");

            // The same override flag in a production-like mode must NOT downgrade.
            var phase10ProdState = new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore();
            var phase10ProdPolicy = new DataVanger.Shared.Updates.UpdatePolicy
            {
                Mode = DataVanger.Shared.Updates.UpdateMode.AutoApplyFeedsOnly, FeedId = Phase10FeedId, AllowDowngradeInDevelopmentMode = true,
            };
            Phase10NewServiceWithPolicy(phase10ProdState, phase10ProdPolicy, Phase10BuildTransport(50, System.Text.Encoding.UTF8.GetBytes("v50"))).CheckAndApply();
            var phase10ProdResult = Phase10NewServiceWithPolicy(phase10ProdState, phase10ProdPolicy,
                Phase10BuildTransport(49, System.Text.Encoding.UTF8.GetBytes("v49"))).CheckAndApply();
            assert(!phase10ProdResult.Succeeded && phase10ProdResult.Kind == DataVanger.Shared.Updates.UpdateResultKind.DowngradeRejected,
                "Phase10 downgrade override must NOT apply outside Development/Test modes.");
        }

        // 28. Health snapshot exposes update state without any verdict.
        {
            var phase10HealthService = Phase10NewService(new DataVanger.Engine.Updates.SignedUpdates.InMemoryUpdateStateStore(),
                5, System.Text.Encoding.UTF8.GetBytes("health"));
            phase10HealthService.CheckAndApply();
            var phase10HealthSnapshot = phase10HealthService.GetHealth();
            assert(phase10HealthSnapshot.IsEnabled && phase10HealthSnapshot.HighestSequence == 5
                   && phase10HealthSnapshot.Status == "Healthy" && !phase10HealthSnapshot.IsConfirmedMalware,
                "Phase10 health snapshot must expose enabled/healthy update state without any verdict.");
        }

        // 29. HTTP transport is opt-in and fail-closed (Phase 14). When disabled/unconfigured it
        //     performs NO network I/O and returns null instead of throwing. (Behavior change from
        //     the prior NotSupportedException stub; full bounded coverage lives in
        //     SignedUpdateHttpTransportTests.) It still never connects on its own.
        {
            var phase10Transport = new DataVanger.Engine.Updates.SignedUpdates.HttpUpdateTransport(
                DataVanger.Engine.Updates.SignedUpdates.HttpUpdateTransportOptions.Disabled);
            assert(phase10Transport.GetManifestBytes() is null,
                "Phase10 HTTP transport must perform no I/O and return null when disabled/unconfigured.");
        }
    }
}

// ── Phase 2 / Step 11: Service IPC and UI Integration test section ───────────
// Wrapped in a uniquely-named file-local helper so this section introduces NO
// top-level locals (avoids duplicate-local regressions). Deterministic,
// in-memory only: no admin, no installed service, no real named pipes, no
// network, no background loops. Local names use the phase11* convention.
//
// xUnit1031-deferred: this is a synchronous, file-local HELPER class invoked by the async
// mega-[Fact] — it is NOT a test method, so its blocking GetAwaiter/GetResult calls are outside
// xUnit1031's scope. They are kept blocking on purpose: BuildRouter has an `out` parameter and
// Send/Run are synchronous, so converting them to async would require out-parameter-async or
// async-void (both forbidden). Phase-08 async cleanup applies only to the Fact body.
// Decomposed (phase 09): invoked as a dedicated [Fact] by ServiceIpcTests. Promoted
// from file-local to internal so the per-subsystem test class can call Run(...).
internal static class Phase11ServiceIpcUi
{
    private static DataVanger.Service.Ipc.DataVangerServiceCommandRouter BuildRouter(
        out DataVanger.Service.Ipc.DataVangerServiceCommandContext phase11Context,
        DataVanger.Shared.Quarantine.IQuarantineService? phase11Quarantine = null,
        string phase11HostKind = "TestHost",
        Action? phase11ShutdownCallback = null,
        Func<System.Collections.Generic.IReadOnlyList<DataVanger.Shared.Ipc.SecurityEventDto>>? phase11Events = null)
    {
        var phase11Runtime = new DataVanger.Service.Runtime.DataVangerServiceRuntime();
        phase11Runtime.StartAsync(System.Threading.CancellationToken.None).GetAwaiter().GetResult();

        phase11Context = new DataVanger.Service.Ipc.DataVangerServiceCommandContext
        {
            Runtime = phase11Runtime,
            Quarantine = phase11Quarantine,
            HostKind = phase11HostKind,
            DevelopmentHostShutdownCallback = phase11ShutdownCallback,
            RecentEventsProvider = phase11Events,
        };

        return new DataVanger.Service.Ipc.DataVangerServiceCommandRouter(phase11Context);
    }

    private static DataVanger.Shared.Ipc.DataVangerResponse Send(
        DataVanger.Shared.Ipc.IDataVangerServiceClient phase11Client,
        DataVanger.Shared.Ipc.DataVangerRequest phase11Request,
        System.Threading.CancellationToken phase11Token = default)
        => phase11Client.SendAsync(phase11Request, phase11Token).GetAwaiter().GetResult();

    public static void Run(Action<bool, string> assert)
    {
        // 1. InMemoryIpcClient_CanPingService
        {
            var phase11Router = BuildRouter(out _);
            var phase11Client = new DataVanger.Infrastructure.Ipc.InMemoryDataVangerServiceClient(phase11Router);
            var phase11Response = Send(phase11Client,
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.Ping));
            assert(phase11Response.Success && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.Ok,
                "Phase11 in-memory client must ping the service successfully.");
            assert(phase11Response.Message == "pong",
                "Phase11 ping response must carry the 'pong' message.");
        }

        // 2. CommandRouter_RejectsUnknownCommand
        {
            var phase11Router = BuildRouter(out _);
            var phase11Response = phase11Router.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.Unknown))
                .GetAwaiter().GetResult();
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.UnknownCommand,
                "Phase11 router must reject an unknown command with a structured error.");
        }

        // 3. CommandRouter_RejectsMalformedPayload
        {
            var phase11Router = BuildRouter(out _);
            var phase11Malformed = new DataVanger.Shared.Ipc.DataVangerRequest
            {
                CommandType = DataVanger.Shared.Ipc.DataVangerCommandType.StartCustomScan,
                PayloadJson = "{ this is : not valid json ",
            };
            var phase11Response = phase11Router.HandleAsync(phase11Malformed).GetAwaiter().GetResult();
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.BadRequest,
                "Phase11 router must reject a malformed payload with a structured BadRequest.");
        }

        // 4. CommandRouter_ReturnsServiceStatus
        {
            var phase11Router = BuildRouter(out _);
            var phase11Response = phase11Router.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.GetServiceStatus))
                .GetAwaiter().GetResult();
            assert(phase11Response.Success, "Phase11 GetServiceStatus must succeed.");
            DataVanger.Infrastructure.Ipc.IpcSerialization.TryDeserializePayload<DataVanger.Shared.Ipc.ServiceStatusSnapshot>(
                phase11Response.PayloadJson, out var phase11Snapshot);
            assert(phase11Snapshot is not null && phase11Snapshot.State == "Running",
                "Phase11 service status must report the Running state.");
            assert(phase11Snapshot is not null && !phase11Snapshot.HasActiveProtection,
                "Phase11 service status must NOT claim active protection (anti-security-theater).");
        }

        // 5. CommandRouter_ReturnsModuleStatus
        {
            var phase11Router = BuildRouter(out _);
            var phase11Response = phase11Router.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.GetModuleStatus))
                .GetAwaiter().GetResult();
            assert(phase11Response.Success, "Phase11 GetModuleStatus must succeed.");
            DataVanger.Infrastructure.Ipc.IpcSerialization.TryDeserializePayload<DataVanger.Shared.Ipc.ModuleStatusListDto>(
                phase11Response.PayloadJson, out var phase11Modules);
            assert(phase11Modules is not null && phase11Modules.Count > 0,
                "Phase11 module status must return at least one module.");
        }

        // 6. IpcClient_HandlesServiceUnavailable
        {
            var phase11Client = new DataVanger.Infrastructure.Ipc.UnavailableDataVangerServiceClient();
            var phase11Response = Send(phase11Client,
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.GetServiceStatus));
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.ServiceUnavailable,
                "Phase11 unavailable client must return a structured ServiceUnavailable response.");
            assert(!phase11Client.IsAvailable,
                "Phase11 unavailable client must report IsAvailable=false.");
        }

        // 7. IpcClient_HandlesTimeout
        {
            var phase11Router = BuildRouter(out _);
            var phase11SlowHost = new DataVanger.Infrastructure.Ipc.InMemoryDataVangerServiceHost(
                phase11Router, TimeSpan.FromSeconds(5));
            var phase11Options = new DataVanger.Infrastructure.Ipc.IpcOptions { RequestTimeout = TimeSpan.FromMilliseconds(40) };
            var phase11Client = new DataVanger.Infrastructure.Ipc.InMemoryDataVangerServiceClient(phase11SlowHost, phase11Options);
            var phase11Response = Send(phase11Client,
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.Ping));
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.Timeout,
                "Phase11 client must surface a structured Timeout when the host is too slow.");
        }

        // 8. IpcClient_HandlesCancellation
        {
            var phase11Router = BuildRouter(out _);
            var phase11Client = new DataVanger.Infrastructure.Ipc.InMemoryDataVangerServiceClient(phase11Router);
            using var phase11Cancellation = new System.Threading.CancellationTokenSource();
            phase11Cancellation.Cancel();
            var phase11Response = Send(phase11Client,
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.Ping),
                phase11Cancellation.Token);
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.Cancelled,
                "Phase11 client must surface a structured Cancelled response for a cancelled token.");
        }

        // 9. IpcClient_RejectsOversizedMessage
        {
            var phase11Router = BuildRouter(out _);
            var phase11Options = new DataVanger.Infrastructure.Ipc.IpcOptions { MaxMessageBytes = 512 };
            var phase11Client = new DataVanger.Infrastructure.Ipc.InMemoryDataVangerServiceClient(phase11Router, phase11Options);
            var phase11Request = new DataVanger.Shared.Ipc.DataVangerRequest
            {
                CommandType = DataVanger.Shared.Ipc.DataVangerCommandType.GetConfigurationSummary,
                PayloadJson = new string('x', 4096),
            };
            var phase11Response = Send(phase11Client, phase11Request);
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.PayloadTooLarge,
                "Phase11 client must reject an oversized message with PayloadTooLarge.");
        }

        // 10. UiConnectionModel_ShowsUnavailableWhenServiceMissing
        {
            var phase11Model = new DataVanger.Shared.Ipc.UiServiceConnectionModel(
                DataVanger.Shared.Ipc.ServiceConnectionStatus.NotRunning);
            assert(phase11Model.IsUnavailable && !phase11Model.IsConnected,
                "Phase11 UI model must report unavailable when the service is not running.");
            assert(phase11Model.StatusText == "Service: Not running",
                "Phase11 UI model must show an honest 'Not running' label.");
            assert(!phase11Model.ShowServiceProtectionAsActive,
                "Phase11 UI model must never show service protection as active when unavailable.");
        }

        // 11. UiConnectionModel_DisablesRuntimeControlsWhenUnavailable
        {
            var phase11Unavailable = new DataVanger.Shared.Ipc.UiServiceConnectionModel(
                DataVanger.Shared.Ipc.ServiceConnectionStatus.Unreachable);
            assert(!phase11Unavailable.AreServiceRuntimeControlsEnabled,
                "Phase11 UI model must disable runtime-only controls when the service is unreachable.");

            var phase11Connected = new DataVanger.Shared.Ipc.UiServiceConnectionModel(
                DataVanger.Shared.Ipc.ServiceConnectionStatus.Connected, serviceReportsActiveProtection: true);
            assert(phase11Connected.AreServiceRuntimeControlsEnabled
                   && phase11Connected.ShowServiceProtectionAsActive,
                "Phase11 UI model must enable runtime controls and may show active protection only when connected and honest.");
        }

        // 12. QuarantineCommand_RequiresValidItemId
        {
            var phase11Router = BuildRouter(out _, phase11Quarantine: new Phase11FakeQuarantineService());
            var phase11Request = new DataVanger.Shared.Ipc.DataVangerRequest
            {
                CommandType = DataVanger.Shared.Ipc.DataVangerCommandType.RestoreQuarantineItem,
                PayloadJson = DataVanger.Infrastructure.Ipc.IpcSerialization.SerializePayload(
                    new DataVanger.Shared.Ipc.QuarantineRequestDto
                    {
                        Operation = DataVanger.Shared.Ipc.QuarantineOperation.Restore,
                        ItemId = "",
                    }),
            };
            var phase11Response = phase11Router.HandleAsync(phase11Request).GetAwaiter().GetResult();
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.BadRequest
                   && phase11Response.ErrorCode == "InvalidItemId",
                "Phase11 quarantine restore must require a valid item id.");

            // List with the same fake service must still succeed and be bounded.
            var phase11ListResponse = phase11Router.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.ListQuarantineItems))
                .GetAwaiter().GetResult();
            assert(phase11ListResponse.Success,
                "Phase11 quarantine list must succeed with a bound quarantine service.");
        }

        // 13. ScanCommand_ReturnsOperationId
        {
            var phase11Router = BuildRouter(out _);
            var phase11Response = phase11Router.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.StartQuickScan))
                .GetAwaiter().GetResult();
            assert(phase11Response.Success, "Phase11 StartQuickScan must succeed.");
            DataVanger.Infrastructure.Ipc.IpcSerialization.TryDeserializePayload<DataVanger.Shared.Ipc.ServiceCommandResult>(
                phase11Response.PayloadJson, out var phase11Result);
            assert(phase11Result is not null && !string.IsNullOrWhiteSpace(phase11Result.OperationId),
                "Phase11 scan command must return a non-empty operation id.");
        }

        // 13b. ScanCommand rejects unsafe custom paths (path traversal).
        {
            var phase11Router = BuildRouter(out _);
            var phase11Request = new DataVanger.Shared.Ipc.DataVangerRequest
            {
                CommandType = DataVanger.Shared.Ipc.DataVangerCommandType.StartCustomScan,
                PayloadJson = DataVanger.Infrastructure.Ipc.IpcSerialization.SerializePayload(
                    new DataVanger.Shared.Ipc.ScanRequestDto
                    {
                        Kind = DataVanger.Shared.Ipc.ScanRequestKind.Custom,
                        Paths = new[] { @"C:\Users\..\..\Windows\System32" },
                    }),
            };
            var phase11Response = phase11Router.HandleAsync(phase11Request).GetAwaiter().GetResult();
            assert(!phase11Response.Success
                   && phase11Response.StatusCode == DataVanger.Shared.Ipc.IpcStatusCode.BadRequest,
                "Phase11 custom scan must reject path traversal.");
        }

        // 14. EventQuery_IsBounded
        {
            var phase11ManyEvents = new System.Collections.Generic.List<DataVanger.Shared.Ipc.SecurityEventDto>();
            for (int phase11I = 0; phase11I < 500; phase11I++)
            {
                phase11ManyEvents.Add(new DataVanger.Shared.Ipc.SecurityEventDto
                {
                    EventId = "evt-" + phase11I,
                    Severity = "Informational",
                    Title = "telemetry",
                    Classification = "Telemetry",
                });
            }

            var phase11Router = BuildRouter(out _, phase11Events: () => phase11ManyEvents);
            var phase11Request = new DataVanger.Shared.Ipc.DataVangerRequest
            {
                CommandType = DataVanger.Shared.Ipc.DataVangerCommandType.GetRecentEvents,
                PayloadJson = DataVanger.Infrastructure.Ipc.IpcSerialization.SerializePayload(
                    new DataVanger.Shared.Ipc.EventQueryRequestDto { Limit = 100000 }),
            };
            var phase11Response = phase11Router.HandleAsync(phase11Request).GetAwaiter().GetResult();
            assert(phase11Response.Success, "Phase11 event query must succeed.");
            DataVanger.Infrastructure.Ipc.IpcSerialization.TryDeserializePayload<DataVanger.Shared.Ipc.EventQueryResultDto>(
                phase11Response.PayloadJson, out var phase11EventResult);
            assert(phase11EventResult is not null
                   && phase11EventResult.AppliedLimit == DataVanger.Shared.Ipc.EventQueryRequestDto.MaxLimit
                   && phase11EventResult.Events.Count == DataVanger.Shared.Ipc.EventQueryRequestDto.MaxLimit,
                "Phase11 event query must be bounded to the hard maximum.");
            assert(phase11EventResult is not null && phase11EventResult.TotalAvailable == 500,
                "Phase11 event query must report total available before bounding.");
        }

        // 15. DevelopmentHost_ShutdownDoesNotAffectProductionService
        {
            // Production service host: shutdown must be refused.
            var phase11ProdRouter = BuildRouter(out _, phase11HostKind: "Service");
            var phase11ProdResponse = phase11ProdRouter.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.ShutdownDevelopmentHost))
                .GetAwaiter().GetResult();
            assert(!phase11ProdResponse.Success
                   && phase11ProdResponse.ErrorCode == "ProductionShutdownRefused",
                "Phase11 ShutdownDevelopmentHost must be refused on a production service host.");

            // Development host: shutdown is acknowledged and invokes the callback.
            bool phase11ShutdownInvoked = false;
            var phase11DevRouter = BuildRouter(out _, phase11HostKind: "DevelopmentHost",
                phase11ShutdownCallback: () => phase11ShutdownInvoked = true);
            var phase11DevResponse = phase11DevRouter.HandleAsync(
                DataVanger.Shared.Ipc.DataVangerRequest.Create(DataVanger.Shared.Ipc.DataVangerCommandType.ShutdownDevelopmentHost))
                .GetAwaiter().GetResult();
            assert(phase11DevResponse.Success && phase11ShutdownInvoked,
                "Phase11 ShutdownDevelopmentHost must be honored on a development/test host.");
        }

        // 16. Allowlist + anti-FP structural guarantees.
        {
            assert(!DataVanger.Shared.Ipc.DataVangerCommandCatalog.IsAllowed(DataVanger.Shared.Ipc.DataVangerCommandType.Unknown),
                "Phase11 allowlist must reject the Unknown command.");
            assert(DataVanger.Shared.Ipc.DataVangerCommandCatalog.IsAllowed(DataVanger.Shared.Ipc.DataVangerCommandType.Ping),
                "Phase11 allowlist must allow Ping.");

            // No IPC DTO exposes a ConfirmedMalware surface.
            var phase11EventDto = new DataVanger.Shared.Ipc.SecurityEventDto();
            assert(phase11EventDto.Classification == "Telemetry",
                "Phase11 security-event DTO classification must default to Telemetry, never a verdict.");
        }
    }
}

// Minimal in-test quarantine service used only by the Phase 11 quarantine
// routing checks. It is a passive fake: it never classifies, never confirms
// malware, and returns an empty store. No real cryptography or files.
file sealed class Phase11FakeQuarantineService : DataVanger.Shared.Quarantine.IQuarantineService
{
    public Task<DataVanger.Shared.Quarantine.QuarantineResult> QuarantineAsync(
        DataVanger.Shared.Quarantine.QuarantineRequest request,
        System.Threading.CancellationToken cancellationToken = default)
        => Task.FromResult(DataVanger.Shared.Quarantine.QuarantineResult.Failure(
            DataVanger.Shared.Quarantine.QuarantineStatus.Unknown, "fake"));

    public Task<DataVanger.Shared.Quarantine.QuarantineRestoreResult> RestoreAsync(
        DataVanger.Shared.Quarantine.QuarantineRestoreRequest request,
        System.Threading.CancellationToken cancellationToken = default)
        => Task.FromResult(DataVanger.Shared.Quarantine.QuarantineRestoreResult.Failure(
            DataVanger.Shared.Quarantine.QuarantineStatus.RecordNotFound, "fake"));

    public Task<DataVanger.Shared.Quarantine.QuarantineIntegrityResult> VerifyAsync(
        string quarantineId,
        System.Threading.CancellationToken cancellationToken = default)
        => Task.FromResult(new DataVanger.Shared.Quarantine.QuarantineIntegrityResult());

    public Task<System.Collections.Generic.IReadOnlyList<DataVanger.Shared.Quarantine.QuarantineIndexEntry>> ListAsync(
        System.Threading.CancellationToken cancellationToken = default)
        => Task.FromResult((System.Collections.Generic.IReadOnlyList<DataVanger.Shared.Quarantine.QuarantineIndexEntry>)
            System.Array.Empty<DataVanger.Shared.Quarantine.QuarantineIndexEntry>());

    public Task<DataVanger.Shared.Quarantine.QuarantineRecord?> GetAsync(
        string quarantineId,
        System.Threading.CancellationToken cancellationToken = default)
        => Task.FromResult<DataVanger.Shared.Quarantine.QuarantineRecord?>(null);
}
