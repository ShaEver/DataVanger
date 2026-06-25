using System;

namespace DataVanger.Detection;

public class DetectionModuleSet
{
    public bool Hash { get; set; } = true;
    public bool Persistence { get; set; } = true;
    public bool Yara { get; set; } = true;
    public bool Authenticode { get; set; } = true;
    public bool Heuristic { get; set; } = true;
    public bool Script { get; set; } = true;
    public bool PE { get; set; } = true;
    public bool Archive { get; set; } = true;
    public bool Document { get; set; } = true;
    public bool BrowserExtension { get; set; } = true;

    public static DetectionModuleSet FastOnly() => new()
    {
        Hash = true,
        Persistence = true,
        Yara = true,
        Authenticode = true,
        Heuristic = false,
        Script = false,
        PE = false,
        Archive = false,
        Document = false,
        BrowserExtension = false
    };

    public static DetectionModuleSet All() => new()
    {
        Hash = true,
        Persistence = true,
        Yara = true,
        Authenticode = true,
        Heuristic = true,
        Script = true,
        PE = true,
        Archive = true,
        Document = true,
        BrowserExtension = true
    };

    /// <summary>
    /// Determines whether a named detection module runs for this profile. Called by
    /// <c>DetectionPipeline.AnalyzeAsync</c> to gate modules at runtime (Fast vs Deep).
    ///
    /// Names match the module <c>Name</c> values registered in
    /// <c>EngineComposition.BuildDefault</c>: <c>HashLookup</c>, <c>Heuristic</c>,
    /// <c>Script</c>, <c>PeStatic</c>, <c>Archive</c>, <c>Document</c>,
    /// <c>BrowserExtension</c>, <c>Yara</c>, <c>Persistence</c>. Unknown names default
    /// to enabled so future/placeholder modules are never silently dropped.
    ///
    /// Anti-FP contract: disabling a module only removes evidence/score signals — it
    /// never adds trust relief — so gating can never create a false positive. It only
    /// makes the Fast profile superficial by design. The trust-granting paths (Hash
    /// whitelist and Authenticode) stay enabled in Fast.
    /// </summary>
    public bool IsEnabled(string moduleName) => moduleName switch
    {
        "HashLookup"       => Hash,
        "Heuristic"        => Heuristic,
        "Script"           => Script,
        "PeStatic"         => PE,
        "Archive"          => Archive,
        "Document"         => Document,
        "BrowserExtension" => BrowserExtension,
        "Yara"             => Yara,
        "Persistence"      => Persistence,
        _                  => true
    };
}
