namespace DataVanger.Memory;

/// <summary>
/// Kinds of suspicious memory observations the scanner can produce.
///
/// None of these kinds, individually, are enough to confirm malware —
/// they raise suspicion only. The Behavioral/Reputation/Classification
/// pipelines decide what to do with them.
/// </summary>
public enum MemoryFindingKind
{
    None = 0,

    /// <summary>PAGE_EXECUTE_READWRITE in private memory.</summary>
    RwxPrivateRegion,

    /// <summary>RX private memory with no backing image (manual map / shellcode candidate).</summary>
    AnonymousExecutableRegion,

    /// <summary>High-entropy bytes inside an executable region (packed / encrypted payload candidate).</summary>
    HighEntropyExecutable,

    /// <summary>MZ/PE magic discovered inside private executable memory (reflective-DLL candidate).</summary>
    ReflectivePeIndicator,

    /// <summary>Image-region inconsistency suggestive of process hollowing.</summary>
    HollowingIndicator,

    /// <summary>Shellcode-like instruction-density / NOP-sled pattern in private executable bytes.</summary>
    ShellcodeLikePattern,

    /// <summary>Loaded module from an unusual path (Temp/AppData) and unsigned.</summary>
    SuspiciousModulePath,
}
