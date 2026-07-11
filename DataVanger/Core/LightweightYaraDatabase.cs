using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DataVanger.Core;

public sealed class LightweightYaraDatabase
{
    private readonly List<LightweightYaraRule> _rules = new();
    public IReadOnlyList<LightweightYaraRule> Rules => _rules;
    public int Count => _rules.Count;

    /// <summary>
    /// Phase 13 — result of the last local rule-pack load (loaded/skipped/failed/limited
    /// counts + per-file reasons). Descriptive only; never affects matching or confirmation.
    /// </summary>
    public RulePackValidationResult Validation { get; private set; } = RulePackValidationResult.Empty;

    // Production entry point (unchanged signature). Applies generous DEFAULT bounds so a
    // pathological local rule pack can never OOM or crash a scan. Configurable limits can be
    // supplied via the overload below (wiring AppSettings limits into the production call site
    // is a minimal future ScanEngine change, outside this phase's allowed files).
    public static LightweightYaraDatabase Load(string signatureRoot)
        => Load(signatureRoot, RulePackLimits.Default);

    /// <summary>
    /// Phase 13 — bounded, offline, defensive local rule-pack loader. Loads ONLY from
    /// &lt;signatureRoot&gt;/yara_rules. Each file is processed independently: a malformed file is
    /// isolated, an oversized file or one that breaks a count/total limit is skipped (Limited),
    /// and a file using YARA constructs the lightweight string engine cannot represent
    /// (module import / include) is skipped (so it can never string-match into a false positive).
    /// Accurate loaded/skipped/failed/limited counts are recorded in <see cref="Validation"/>.
    /// Matching and confirmation semantics are unchanged. No network/download/cloud access.
    /// </summary>
    public static LightweightYaraDatabase Load(string signatureRoot, RulePackLimits limits)
    {
        limits ??= RulePackLimits.Default;
        var db = new LightweightYaraDatabase();
        string rulesRoot = Path.Combine(signatureRoot, "yara_rules");
        Directory.CreateDirectory(rulesRoot);
        EnsureReadme(rulesRoot);

        int loadedRules = 0, skippedFiles = 0, failedFiles = 0, limitedFiles = 0, processedFiles = 0;
        long totalBytes = 0;
        var issues = new List<RulePackIssue>();

        List<string> files;
        try
        {
            var ruleRoots = new List<string> { rulesRoot };
            ruleRoots.AddRange(SignedFeedProjectionDiscovery.GetVerifiedActiveVersionRoots(signatureRoot)
                .Select(root => Path.Combine(root, "yara_rules")).Where(Directory.Exists));
            files = ruleRoots.SelectMany(root => Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
                .Where(p => !Path.GetFileName(p).StartsWith("README", StringComparison.OrdinalIgnoreCase)
                         && (p.EndsWith(".yar", StringComparison.OrdinalIgnoreCase)
                          || p.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)
                          || p.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase) // deterministic limit application
                .ToList();
        }
        catch (Exception ex) when (IsExpectedLoadException(ex))
        {
            db.Validation = new RulePackValidationResult(0, 0, 1, 0,
                new[] { new RulePackIssue("(directory)", "Could not enumerate rule files: " + ex.GetType().Name, "Failed") });
            return db;
        }

        foreach (var path in files)
        {
            string fileName = Path.GetFileName(path);

            if (processedFiles >= limits.MaxRuleFiles)
            {
                limitedFiles++;
                issues.Add(new RulePackIssue(fileName, "Maximum rule-file count reached; remaining files not loaded.", "Limited"));
                continue;
            }

            long size;
            try { size = new FileInfo(path).Length; }
            catch (Exception ex) when (IsExpectedLoadException(ex))
            {
                failedFiles++;
                issues.Add(new RulePackIssue(fileName, "Could not read file metadata: " + ex.GetType().Name, "Failed"));
                continue;
            }

            if (size > limits.MaxRuleFileSizeBytes)
            {
                limitedFiles++;
                issues.Add(new RulePackIssue(fileName, $"File exceeds the {limits.MaxRuleFileSizeBytes / 1024} KB single-file limit.", "Limited"));
                continue;
            }
            if (totalBytes + size > limits.MaxRulePackSizeBytes)
            {
                limitedFiles++;
                issues.Add(new RulePackIssue(fileName, "Total rule-pack size limit reached; file not loaded.", "Limited"));
                continue;
            }

            string content;
            try { content = File.ReadAllText(path); }
            catch (Exception ex) when (IsExpectedLoadException(ex))
            {
                failedFiles++;
                issues.Add(new RulePackIssue(fileName, "Could not read file: " + ex.GetType().Name, "Failed"));
                continue;
            }

            totalBytes += size;
            processedFiles++;

            var unsupported = DetectUnsupportedConstruct(content);
            if (unsupported != null)
            {
                skippedFiles++;
                issues.Add(new RulePackIssue(fileName, unsupported, "Skipped"));
                continue;
            }

            try
            {
                var parsed = ParseRules(content, fileName).ToList();
                if (parsed.Count == 0)
                {
                    skippedFiles++;
                    issues.Add(new RulePackIssue(fileName, "No rules with supported string patterns were found.", "Skipped"));
                    continue;
                }
                foreach (var rule in parsed) db._rules.Add(rule);
                loadedRules += parsed.Count;
            }
            catch (Exception ex) when (IsExpectedLoadException(ex))
            {
                // One malformed rule file must not stop loading the rest - isolate and continue.
                failedFiles++;
                issues.Add(new RulePackIssue(fileName, "Parse error: " + ex.GetType().Name, "Failed"));
                System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to load YARA rule file '{path}': {ex.Message}");
            }
        }

        db.Validation = new RulePackValidationResult(loadedRules, skippedFiles, failedFiles, limitedFiles, issues);
        return db;
    }

    private static bool IsExpectedLoadException(Exception ex) =>
        ex is not OutOfMemoryException
        and not StackOverflowException
        and not AccessViolationException
        and not System.Threading.ThreadAbortException;

    /// <summary>
    /// Detect YARA constructs the lightweight string-only engine cannot represent and that
    /// could otherwise cause a string-only FALSE POSITIVE (module-gated rules). Conservative:
    /// only flags file-scoped `import "..."` / `include "..."` directives. Returns a skip reason
    /// or null. Never throws (regex timeouts degrade to "not detected" → normal parse path).
    /// </summary>
    private static string? DetectUnsupportedConstruct(string raw)
    {
        try
        {
            var timeout = TimeSpan.FromSeconds(1);
            var stripped = Regex.Replace(raw, @"/\*.*?\*/", "", RegexOptions.Singleline, timeout);
            stripped = Regex.Replace(stripped, @"//.*?$", "", RegexOptions.Multiline, timeout);
            if (Regex.IsMatch(stripped, "^\\s*import\\s+\"", RegexOptions.Multiline, timeout))
                return "Unsupported construct: YARA module import (skipped to avoid string-only false positives).";
            if (Regex.IsMatch(stripped, "^\\s*include\\s+\"", RegexOptions.Multiline, timeout))
                return "Unsupported construct: YARA include directive (cannot resolve locally; skipped).";
            return null;
        }
        catch (RegexMatchTimeoutException)
        {
            return null; // fall through to the normal (also-bounded) parse path
        }
    }

    public List<LightweightYaraMatch> ScanFile(string path, int maxScanSizeMB)
    {
        var matches = new List<LightweightYaraMatch>();
        if (_rules.Count == 0) return matches;

        try
        {
            var fi = new FileInfo(path);
            long maxBytes = Math.Max(1, maxScanSizeMB) * 1_048_576L;
            if (fi.Length <= 0 || fi.Length > maxBytes) return matches;

            byte[] bytes = File.ReadAllBytes(path);
            string text = Encoding.Latin1.GetString(bytes);

            foreach (var rule in _rules)
            {
                int matched = 0;
                foreach (var pattern in rule.Patterns)
                {
                    if (pattern.Nocase)
                    {
                        if (text.IndexOf(pattern.Value, StringComparison.OrdinalIgnoreCase) >= 0) matched++;
                    }
                    else if (text.Contains(pattern.Value, StringComparison.Ordinal)) matched++;
                }

                bool ok = rule.MinimumMatches <= 0
                    ? matched == rule.Patterns.Count
                    : matched >= Math.Min(rule.MinimumMatches, rule.Patterns.Count);

                if (ok)
                    matches.Add(new LightweightYaraMatch(rule.Name, rule.Description, rule.Confirmed, rule.Score, matched, rule.Patterns.Count));
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Scan hot path - swallow expected per-file read/parse failures and return collected matches; fatal CLR exceptions are not caught.
        }

        return matches;
    }

    private static IEnumerable<LightweightYaraRule> ParseRules(string raw, string source)
    {
        raw = Regex.Replace(raw, @"/\*.*?\*/", "", RegexOptions.Singleline);
        raw = Regex.Replace(raw, @"//.*?$", "", RegexOptions.Multiline);

        int idx = 0;
        while (true)
        {
            var m = Regex.Match(raw, @"\brule\s+([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            if (!m.Success) yield break;
            int absoluteRule = idx + m.Index;
            string name = m.Groups[1].Value;
            int open = raw.IndexOf('{', absoluteRule + m.Length);
            if (open < 0) yield break;
            int close = FindMatchingBrace(raw, open);
            if (close < 0) yield break;

            string body = raw.Substring(open + 1, close - open - 1);
            var rule = ParseRuleBody(name, body, source);
            if (rule != null) yield return rule;

            idx = close + 1;
            if (idx >= raw.Length) yield break;
            raw = raw.Substring(idx);
            idx = 0;
        }
    }

    private static int FindMatchingBrace(string s, int open)
    {
        int depth = 0;
        bool inString = false;
        for (int i = open; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"' && (i == 0 || s[i - 1] != '\\')) inString = !inString;
            if (inString) continue;
            if (c == '{') depth++;
            else if (c == '}')
            {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    private static LightweightYaraRule? ParseRuleBody(string name, string body, string source)
    {
        var patterns = new List<LightweightYaraPattern>();
        foreach (Match sm in Regex.Matches(body, "\\$[A-Za-z0-9_]+\\s*=\\s*\"((?:\\\\\"|[^\"])*)\"(?<mods>[^\\r\\n]*)", RegexOptions.IgnoreCase))
        {
            string value = Regex.Unescape(sm.Groups[1].Value);
            if (value.Length < 4) continue;
            string mods = sm.Groups["mods"].Value;
            patterns.Add(new LightweightYaraPattern(value, mods.Contains("nocase", StringComparison.OrdinalIgnoreCase)));
        }

        if (patterns.Count == 0) return null;

        string lower = body.ToLowerInvariant();
        int min = patterns.Count;
        var nOfThem = Regex.Match(lower, @"\b(\d+)\s+of\s+them\b");
        if (nOfThem.Success && int.TryParse(nOfThem.Groups[1].Value, out int n)) min = Math.Max(1, n);
        else if (lower.Contains("any of them") || Regex.IsMatch(lower, @"\bor\b")) min = 1;
        else if (lower.Contains("all of them") || Regex.IsMatch(lower, @"\band\b")) min = patterns.Count;

        bool confirmed = Regex.IsMatch(lower, "\\bconfirmed\\s*=\\s*(true|1|\"true\"|\"confirmed\"|\"yes\")")
                      || Regex.IsMatch(lower, "\\bconfidence\\s*=\\s*\"confirmed\"")
                      || Regex.IsMatch(lower, "\\bseverity\\s*=\\s*\"confirmed\"");

        string description = ExtractMetaString(body, "description")
                          ?? ExtractMetaString(body, "family")
                          ?? source;

        int score = confirmed ? RiskThresholds.Critical + 4 : RiskThresholds.High;
        var scoreMatch = Regex.Match(body, @"\bscore\s*=\s*(\d+)", RegexOptions.IgnoreCase);
        if (scoreMatch.Success && int.TryParse(scoreMatch.Groups[1].Value, out int parsedScore))
            score = Math.Clamp(parsedScore, 1, RiskThresholds.Critical + 10);

        return new LightweightYaraRule(name, description, confirmed, score, min, patterns);
    }

    private static string? ExtractMetaString(string body, string key)
    {
        var m = Regex.Match(body, "\\b" + Regex.Escape(key) + "\\s*=\\s*\"([^\"\r\n]+)\"", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }

    private static void EnsureReadme(string rulesRoot)
    {
        string path = Path.Combine(rulesRoot, "README_yara_rules.txt");
        if (File.Exists(path)) return;
        File.WriteAllText(path, """
DataVanger — regras YARA leves

Coloque arquivos .yar ou .yara nesta pasta para ativar assinaturas por padrão textual.
Subconjunto aceito:

rule Example_HighRisk {
  meta:
    description = "Exemplo de regra de alto risco"
    score = 9
  strings:
    $a = "powershell -enc" nocase
    $b = "frombase64string" nocase
  condition:
    all of them
}

Para classificar como CRÍTICO, marque explicitamente:
  confirmed = true

Recomendação: use confirmed=true apenas para assinaturas próprias de altíssima confiança.
Hashes conhecidos continuam sendo a forma mais segura para confirmação e quarentena automática.
""", Encoding.UTF8);
    }
}

public sealed record LightweightYaraPattern(string Value, bool Nocase);

public sealed record LightweightYaraRule(
    string Name,
    string Description,
    bool Confirmed,
    int Score,
    int MinimumMatches,
    IReadOnlyList<LightweightYaraPattern> Patterns);

public sealed record LightweightYaraMatch(
    string RuleName,
    string Description,
    bool Confirmed,
    int Score,
    int MatchedPatterns,
    int TotalPatterns);

// ── Phase 13 — bounded local rule-pack loading models ───────────────────────────────

/// <summary>Bounds for a single local rule-pack load. Invalid/≤0 settings normalize to safe defaults.</summary>
public sealed record RulePackLimits(int MaxRuleFiles, long MaxRuleFileSizeBytes, long MaxRulePackSizeBytes)
{
    public static RulePackLimits Default { get; } = new(5000, 2048L * 1024, 128L * 1024 * 1024);

    /// <summary>Build limits from settings, clamping any ≤0 (invalid) value to the safe default.</summary>
    public static RulePackLimits From(AppSettings settings)
    {
        int files  = settings.YaraMaxRuleFiles      > 0 ? settings.YaraMaxRuleFiles      : 5000;
        int fileKb = settings.YaraMaxRuleFileSizeKB  > 0 ? settings.YaraMaxRuleFileSizeKB  : 2048;
        int packMb = settings.YaraMaxRulePackSizeMB  > 0 ? settings.YaraMaxRulePackSizeMB  : 128;
        return new RulePackLimits(files, fileKb * 1024L, packMb * 1024L * 1024L);
    }
}

/// <summary>One per-file outcome from rule-pack loading. Category is Skipped / Failed / Limited.</summary>
public sealed record RulePackIssue(string FileName, string Reason, string Category);

/// <summary>
/// Accurate, descriptive summary of a local rule-pack load. LoadedRuleCount is the number of
/// rules actually added to the engine; the others are file counts. Skipped/failed/limited files
/// are NOT loaded and can never match. Producing/holding this performs no I/O.
/// </summary>
public sealed record RulePackValidationResult(
    int LoadedRuleCount,
    int SkippedFileCount,
    int FailedFileCount,
    int LimitedFileCount,
    IReadOnlyList<RulePackIssue> Issues)
{
    public static RulePackValidationResult Empty { get; } =
        new(0, 0, 0, 0, Array.Empty<RulePackIssue>());
}
