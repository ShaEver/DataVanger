using System;
using System.Collections.Generic;
using System.Threading;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection.Placeholders;

// =============================================================================
// Placeholder modules.
//
// These types exist to:
//   (a) document the planned extension points described in
//       02_DEEP_SCAN_PIPELINE.md through 08_REPUTATION_ENGINE.md, and
//   (b) provide a compile-time anchor so future PRs can land their
//       implementations without touching the rest of the engine.
//
// Every placeholder is an IDetectionModule that returns no evidence. They are
// NOT registered in the default pipeline (see EngineComposition) — they live
// here as scaffolds. None of them claims to detect anything they don't
// actually detect. The honesty rule is enforced by their empty Analyze
// implementations.
//
// REMOVE the type-level [Obsolete] when wiring a real implementation.
// =============================================================================

[Obsolete("Placeholder — there is no per-file behavioral DETECTION MODULE. The behavioral engine itself IS implemented and is wired on the resident service path (DataVanger.Engine/Behavioral/Runtime/BehavioralRuntimeBinding.cs subscribed to the ETW pipeline in DataVangerServiceRuntime). See 04_BEHAVIORAL_ENGINE.md.")]
public sealed class BehavioralModulePlaceholder : DetectionModuleBase
{
    public override string Name => "BehavioralEngine";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => false;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => Array.Empty<Evidence>();
}

[Obsolete("Placeholder — there is no per-file memory DETECTION MODULE. The memory scanner itself IS implemented (DataVanger/Memory/MemoryScannerEngine.cs) and runs standalone; resident-path activation in the service is a follow-up (requires extracting DataVanger.Memory.* into a shared library). See 05_MEMORY_SCANNER.md.")]
public sealed class MemoryScannerPlaceholder : DetectionModuleBase
{
    public override string Name => "MemoryScanner";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => false;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => Array.Empty<Evidence>();
}

[Obsolete("Placeholder — there is no per-file ETW/AMSI DETECTION MODULE. Real ETW runtime telemetry is implemented (DataVanger.Infrastructure/Etw/WindowsEtwRuntimeProvider.cs) and now feeds the behavioral runtime binding on the resident service path; AMSI uses an in-memory content analyzer (no real amsi.dll yet). See 06_ETW_AMSI_INTEGRATION.md.")]
public sealed class EtwAmsiModulePlaceholder : DetectionModuleBase
{
    public override string Name => "EtwAmsi";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => false;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => Array.Empty<Evidence>();
}

// Self-protection has graduated from placeholder to its own subsystem
// (see DataVanger.SelfProtection.SelfProtectionManager). The detection
// module shape never fitted self-protection — it produces TamperEvents
// on the behavioral bus, not per-target Evidence. We keep this scaffold
// in place purely as a documentation anchor so a future PR could add a
// detection module that surfaces tamper history for the active scan.
[Obsolete("Self-protection now lives in DataVanger.SelfProtection. This scaffold is retained only for shape parity with the other placeholders and is not registered.")]
public sealed class SelfProtectionPlaceholder : DetectionModuleBase
{
    public override string Name => "SelfProtection";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.None;
    public override bool Supports(ScanTarget target, ScanContext context) => false;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => Array.Empty<Evidence>();
}

[Obsolete("Placeholder — Cloud reputation adapter not implemented. See 08_REPUTATION_ENGINE.md.")]
public sealed class CloudReputationPlaceholder : DetectionModuleBase
{
    public override string Name => "CloudReputation";
    public override DetectionModuleCapabilities Capabilities => DetectionModuleCapabilities.NeedsHash;
    public override bool Supports(ScanTarget target, ScanContext context) => false;
    protected override IReadOnlyList<Evidence> Analyze(ScanTarget target, ScanContext context, CancellationToken cancellationToken)
        => Array.Empty<Evidence>();
}
