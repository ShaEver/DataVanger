using System;
using System.Collections.Generic;
using DataVanger.Core;
using DataVanger.Core.Abstractions;
#if YARA_REAL
using System.IO;
using dnYara;
#endif

namespace DataVanger.Infrastructure;

/// <summary>
/// Optional real-YARA backend behind the existing <see cref="IYaraEngine"/>
/// abstraction.
///
/// <para>
/// Build/restore safety: this file compiles with <b>no external NuGet package</b>
/// in the default configuration. The real libyara integration is guarded by the
/// <c>YARA_REAL</c> compilation symbol, which must be enabled together with a
/// verified <c>dnYara</c> <c>PackageReference</c> on Windows/.NET (see
/// DataVanger.csproj for the enablement note). Until then,
/// <see cref="TryCreate"/> returns <c>null</c> and
/// <see cref="DataVanger.Engine.EngineComposition"/> keeps the guaranteed
/// <see cref="LightweightYaraDatabase"/> fallback via <see cref="YaraEngineAdapter"/>.
/// </para>
///
/// <para>
/// Safety invariant: real external matches are always emitted with
/// <c>Confirmed = false</c> and <c>Score = 0</c>, so they can never raise
/// <see cref="Evidence.CanConfirmMalware"/> or
/// <see cref="EvidenceStrength.Confirmed"/> through
/// <see cref="DataVanger.Detection.YaraDetectionModule"/>. Malware confirmation
/// stays exclusive to curated lightweight rules.
/// </para>
/// </summary>
public sealed class LibyaraEngine : IYaraEngine, IDisposable
{
    /// <summary>Maximum length of any rule-derived string surfaced as evidence.</summary>
    private const int MaxExposedTextLength = 100;

    /// <summary>
    /// True when the real libyara backend is compiled in (the <c>YARA_REAL</c> symbol is
    /// defined for this assembly). This is the single verifiable code fact behind the
    /// <c>real-libyara</c> module-status claim. The status matrix lives in DataVanger.Shared
    /// (which cannot see this symbol), so a regression test asserts the matrix state matches
    /// this probe — disabling the symbol without updating the matrix then breaks the build.
    /// </summary>
    public static bool RealBackendCompiledIn =>
#if YARA_REAL
        true;
#else
        false;
#endif

    /// <summary>
    /// Attempts to build a real-YARA engine from a local rules directory.
    /// Returns <c>null</c> (so callers fall back to the lightweight engine) when
    /// the real backend is not compiled in, the native library cannot load, the
    /// directory is missing, or no valid rules compile. Never throws for the
    /// expected native/load failures.
    /// </summary>
    public static LibyaraEngine? TryCreate(string yaraRulesDirectory, Action<string>? log = null)
    {
#if YARA_REAL
        try
        {
            var engine = new LibyaraEngine(yaraRulesDirectory, log);
            if (engine.RuleCount > 0) return engine;

            engine.Dispose();
            log?.Invoke("[DataVanger] Real YARA backend compiled 0 usable rules; using lightweight fallback.");
            return null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            // Fallback-first: ANY real-backend failure degrades to the lightweight engine
            // — a missing/incompatible native libyara (DllNotFoundException /
            // BadImageFormatException / TypeLoadException / FileLoadException) or a dnYara
            // backend error. The exact exception type is surfaced for native-load
            // diagnostics; fatal CLR conditions (OOM/StackOverflow) are not caught.
            log?.Invoke($"[DataVanger] Real YARA backend unavailable ({ex.GetType().Name}): {ex.Message}. Using lightweight fallback.");
            return null;
        }
#else
        _ = yaraRulesDirectory;
        log?.Invoke("[DataVanger] Real YARA backend not compiled in (define YARA_REAL + add a verified dnYara package). Using lightweight fallback.");
        return null;
#endif
    }

#if YARA_REAL
    // The native YARA library must be initialised (yr_initialize) before any Compiler,
    // Scanner or CompiledRules is created, and finalised (yr_finalize) only after all of
    // them are released. dnYara models this with YaraContext, so the engine owns a single
    // context for its whole lifetime and disposes it LAST (see Dispose).
    private readonly YaraContext _context;
    private readonly CompiledRules? _rules;
    private readonly Scanner _scanner;
    private bool _disposed;

    public int RuleCount { get; }

    private LibyaraEngine(string yaraRulesDirectory, Action<string>? log)
    {
        _context = new YaraContext();
        try
        {
            _scanner = new Scanner();

            if (!Directory.Exists(yaraRulesDirectory))
            {
                log?.Invoke($"[DataVanger] YARA rules directory '{yaraRulesDirectory}' not found; real backend has 0 rules.");
                _rules = null;
                RuleCount = 0;
                return;
            }

            using var compiler = new Compiler();
            int added = 0;
            foreach (var path in Directory.EnumerateFiles(yaraRulesDirectory, "*.*", SearchOption.AllDirectories))
            {
                if (!path.EndsWith(".yar", StringComparison.OrdinalIgnoreCase)
                    && !path.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    compiler.AddRuleFile(path);
                    added++;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    // One malformed rule file must not stop loading the rest.
                    log?.Invoke($"[DataVanger] Skipped invalid YARA rule file '{path}': {ex.Message}");
                }
            }

            try
            {
                _rules = added > 0 ? compiler.Compile() : null;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                // A whole-pack compile failure must not crash construction: report 0 rules
                // so TryCreate falls back to the lightweight engine.
                log?.Invoke($"[DataVanger] YARA rule compilation failed: {ex.Message}. Using lightweight fallback.");
                _rules = null;
            }
            RuleCount = _rules is null ? 0 : added;
        }
        catch (Exception)
        {
            // Construction failed after yr_initialize (e.g. the native library could not
            // load): release native resources in the correct order — compiled rules first,
            // then the context — before propagating to TryCreate's fallback handler.
            _rules?.Dispose();
            _context.Dispose();
            GC.SuppressFinalize(_context);
            throw;
        }
    }

    public IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB)
    {
        if (_disposed || _rules is null) return Array.Empty<LightweightYaraMatch>();
        try
        {
            var results = _scanner.ScanFile(filePath, _rules);
            if (results is null || results.Count == 0) return Array.Empty<LightweightYaraMatch>();

            var list = new List<LightweightYaraMatch>(results.Count);
            foreach (var r in results)
            {
                string ruleName = Truncate(r.MatchingRule?.Identifier ?? "yara_rule");
                int matchedPatterns = r.Matches?.Count ?? 0;
                // Real external matches are ALWAYS non-confirming.
                list.Add(new LightweightYaraMatch(
                    RuleName: ruleName,
                    Description: "regra YARA externa",
                    Confirmed: false,
                    Score: 0,
                    MatchedPatterns: matchedPatterns,
                    TotalPatterns: matchedPatterns));
            }
            return list;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            // A scan failure on a single file is non-fatal: no match.
            return Array.Empty<LightweightYaraMatch>();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Reverse order of acquisition: rules first, then yr_finalize via the context.
        _rules?.Dispose();
        _context.Dispose();
        GC.SuppressFinalize(_context);
    }

    private static string Truncate(string value) =>
        string.IsNullOrEmpty(value) || value.Length <= MaxExposedTextLength
            ? value
            : value.Substring(0, MaxExposedTextLength);
#else
    // Default build: the real backend is not compiled in. The type still exists so
    // the composition/fallback wiring is fully in place, but TryCreate never
    // returns an instance, so EngineComposition always uses the lightweight engine.
    public int RuleCount => 0;

    public IReadOnlyList<LightweightYaraMatch> Scan(string filePath, int maxScanSizeMB) =>
        Array.Empty<LightweightYaraMatch>();

    public void Dispose() { }
#endif
}
