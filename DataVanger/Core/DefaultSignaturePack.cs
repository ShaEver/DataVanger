using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DataVanger.Core;

/// <summary>
/// Snapshot of how much detection data is loaded, used to surface an honest status to
/// the operator (a scanner with no signatures is heuristic-only / "blind").
/// </summary>
public sealed class DetectionSignatureStatus
{
    public int TotalHashes { get; init; }
    public int KnownMalicious { get; init; }
    public int YaraRules { get; init; }

    /// <summary>No hashes and no YARA rules — detection is purely heuristic.</summary>
    public bool IsBlind { get; init; }

    /// <summary>Only the bundled baseline (e.g. the EICAR test signature) is present.</summary>
    public bool IsBaselineOnly { get; init; }
}

/// <summary>
/// Seeds the bundled default detection pack (shipped under
/// <c>&lt;app&gt;/Signatures.default</c>, see that folder's README) into the user's writable
/// signature root so the scanner is never blind out of the box.
///
/// Seeding is <b>idempotent and additive</b>: existing user entries are preserved and only
/// missing default hashes/rules are added, so it is safe to call on every startup and it
/// naturally picks up new defaults shipped in later versions. The default pack intentionally
/// contains only the industry-standard EICAR test signature — the one "malware" that is safe
/// to distribute — which exercises the confirm + auto-quarantine path end to end without
/// false-positive risk.
/// </summary>
public static class DefaultSignaturePack
{
    public const string MaliciousFileName = "known_malicious_sha256.txt";

    /// <summary>Folder next to the executable where the bundled pack is copied by the build.</summary>
    public static string DefaultsRoot => Path.Combine(AppContext.BaseDirectory, "Signatures.default");

    /// <summary>The malicious hashes shipped in the bundled default pack (upper-case, normalized).</summary>
    public static IReadOnlyCollection<string> BaselineMaliciousHashes()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string src = Path.Combine(DefaultsRoot, MaliciousFileName);
        if (File.Exists(src))
        {
            foreach (var line in File.ReadLines(src))
            {
                var h = SignatureDatabase.ParseHashLine(line);
                if (h != null) set.Add(h);
            }
        }
        return set;
    }

    /// <summary>
    /// Ensures the bundled defaults are present under <paramref name="signatureRoot"/> without
    /// overwriting user-edited content. Best-effort: a failure is recorded but never throws.
    /// </summary>
    public static void EnsureSeeded(string signatureRoot)
    {
        if (string.IsNullOrWhiteSpace(signatureRoot)) return;
        try
        {
            Directory.CreateDirectory(signatureRoot);
            SeedHashes(signatureRoot);
            SeedYaraRules(signatureRoot);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Seeding is best-effort: a degraded/un-seeded pack must be observable but never fatal.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to seed default signature pack: {ex.Message}");
        }
    }

    private static void SeedHashes(string signatureRoot)
    {
        var defaults = BaselineMaliciousHashes();
        if (defaults.Count == 0) return;

        string target = Path.Combine(signatureRoot, MaliciousFileName);
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(target))
        {
            foreach (var line in File.ReadLines(target))
            {
                var h = SignatureDatabase.ParseHashLine(line);
                if (h != null) existing.Add(h);
            }
        }

        var missing = defaults.Where(h => !existing.Contains(h)).ToList();
        if (missing.Count == 0) return;

        var sb = new StringBuilder();
        bool fresh = !File.Exists(target) || new FileInfo(target).Length == 0;
        if (fresh)
        {
            sb.Append("# DataVanger — base de hashes maliciosos (semeada do pacote padrão).\n");
            sb.Append("# Inclui a assinatura de teste EICAR. Acrescente seus hashes SHA-256 abaixo.\n");
        }
        foreach (var h in missing) sb.Append(h).Append('\n');
        File.AppendAllText(target, sb.ToString());
    }

    private static void SeedYaraRules(string signatureRoot)
    {
        string srcDir = Path.Combine(DefaultsRoot, "yara_rules");
        if (!Directory.Exists(srcDir)) return;

        string destDir = Path.Combine(signatureRoot, "yara_rules");
        Directory.CreateDirectory(destDir);
        foreach (var src in Directory.EnumerateFiles(srcDir, "*.*")
                     .Where(p => p.EndsWith(".yar", StringComparison.OrdinalIgnoreCase)
                              || p.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)))
        {
            string dest = Path.Combine(destDir, Path.GetFileName(src));
            if (!File.Exists(dest)) File.Copy(src, dest);
        }
    }

    /// <summary>Describes how much detection data is loaded for an honest UI status line.</summary>
    public static DetectionSignatureStatus Describe(SignatureDatabase db, LightweightYaraDatabase yara)
    {
        int baseline = BaselineMaliciousHashes().Count;
        int malicious = db.KnownMalicious.Count + db.UserBlacklist.Count;
        bool blind = db.TotalHashes == 0 && yara.Count == 0;
        bool baselineOnly = !blind
            && yara.Count == 0
            && db.KnownSafe.Count == 0
            && db.UserWhitelist.Count == 0
            && malicious > 0
            && malicious <= baseline;

        return new DetectionSignatureStatus
        {
            TotalHashes = db.TotalHashes,
            KnownMalicious = malicious,
            YaraRules = yara.Count,
            IsBlind = blind,
            IsBaselineOnly = baselineOnly,
        };
    }
}
