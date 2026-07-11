using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DataVanger.Reputation;

namespace DataVanger.Core;

public sealed class AnalysisResult
{
    public int Score => Evidence.Sum(e => e.ScoreDelta);
    public List<Evidence> Evidence { get; } = new();
    public bool HasHits => Evidence.Count > 0;

    public void Add(string category, string description, int score, EvidenceStrength strength, bool canConfirm = false)
    {
        Evidence.Add(new Evidence
        {
            Category = category,
            Description = description,
            ScoreDelta = score,
            Strength = strength,
            CanConfirmMalware = canConfirm
        });
    }
}

public static class EvidenceService
{
    public static List<Evidence> FromReasons(IEnumerable<string> reasons)
    {
        return reasons
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(r => new Evidence
            {
                Category = InferCategory(r),
                Description = r,
                ScoreDelta = 0,
                Strength = InferStrength(r),
                CanConfirmMalware = r.Contains("malware conhecido", StringComparison.OrdinalIgnoreCase)
                    || r.Contains("confirmada", StringComparison.OrdinalIgnoreCase)
            })
            .ToList();
    }

    public static List<Evidence> Merge(IEnumerable<Evidence> existing, IEnumerable<string> reasons)
    {
        var merged = existing.ToList();
        var seen = new HashSet<string>(merged.Select(e => e.Description), StringComparer.OrdinalIgnoreCase);
        foreach (var evidence in FromReasons(reasons))
        {
            if (seen.Add(evidence.Description)) merged.Add(evidence);
        }
        return merged;
    }

    private static string InferCategory(string text)
    {
        if (text.Contains("YARA", StringComparison.OrdinalIgnoreCase)) return "Signature";
        if (text.Contains("Hash", StringComparison.OrdinalIgnoreCase)) return "Reputation";
        if (text.Contains("script", StringComparison.OrdinalIgnoreCase) || text.Contains("PowerShell", StringComparison.OrdinalIgnoreCase)) return "Script";
        if (text.Contains("compactado", StringComparison.OrdinalIgnoreCase) || text.Contains("ZIP", StringComparison.OrdinalIgnoreCase)) return "Archive";
        if (text.Contains("persist", StringComparison.OrdinalIgnoreCase) || text.Contains("Startup", StringComparison.OrdinalIgnoreCase)) return "Persistence";
        if (text.Contains("Office", StringComparison.OrdinalIgnoreCase) || text.Contains("PDF", StringComparison.OrdinalIgnoreCase)) return "Document";
        if (text.Contains("Assinado", StringComparison.OrdinalIgnoreCase) || text.Contains("publisher", StringComparison.OrdinalIgnoreCase)) return "Signature";
        return "Heuristic";
    }

    private static EvidenceStrength InferStrength(string text)
    {
        if (text.Contains("malware conhecido", StringComparison.OrdinalIgnoreCase)
            || text.Contains("confirmada", StringComparison.OrdinalIgnoreCase)) return EvidenceStrength.Confirmed;
        if (text.Contains("mascaramento", StringComparison.OrdinalIgnoreCase)
            || text.Contains("dupla extensão", StringComparison.OrdinalIgnoreCase)) return EvidenceStrength.High;
        if (text.Contains("execução", StringComparison.OrdinalIgnoreCase)
            || text.Contains("persist", StringComparison.OrdinalIgnoreCase)) return EvidenceStrength.Medium;
        return EvidenceStrength.Low;
    }
}

public static class ScriptAnalyzer
{
    private static readonly Regex CommentLine = new(@"^\s*(#|//|rem\b|::)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static AnalysisResult AnalyzeFile(string path, bool benignContainer)
    {
        var result = new AnalysisResult();
        try
        {
            var fi = new FileInfo(path);
            if (fi.Length > 2 * 1024 * 1024) return result;
            string text = File.ReadAllText(path);
            return AnalyzeText(text, fi.Extension.ToLowerInvariant(), benignContainer);
        }
        catch (System.Exception)
        {
            return result;
        }
    }

    public static AnalysisResult AnalyzeText(string text, string extension, bool benignContainer)
    {
        var result = new AnalysisResult();
        if (benignContainer || string.IsNullOrWhiteSpace(text)) return result;

        string normalized = NormalizeScript(text);
        string lower = normalized.ToLowerInvariant();
        bool javascriptLike = extension is ".js" or ".jse";

        bool encoded = Regex.IsMatch(lower, @"powershell(\.exe)?[^\r\n]{0,180}(-enc\b|-encodedcommand\b)|frombase64string\s*\(", RegexOptions.IgnoreCase);
        bool longBase64 = Regex.IsMatch(lower, @"[a-z0-9+/]{240,}={0,2}", RegexOptions.IgnoreCase);
        bool dynamicExec = Regex.IsMatch(lower, @"\biex\s*(\(|\s)|invoke-expression|downloadstring|invoke-webrequest|new-object\s+net\.webclient|start-bitstransfer|curl\s+https?://|wget\s+https?://", RegexOptions.IgnoreCase);
        bool downloadPayload = Regex.IsMatch(lower, @"(http|https)://[^\s'""]{8,}.*(start-process|cmd\s*/c|powershell|wscript|rundll32|regsvr32)|urlmon|urldownloadtofile", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        // Require real flag syntax — the bare word "hidden" over-fired on benign .js
        // (log/UI/config strings). "-w hidden" / "windowstyle hidden" still match.
        bool bypass = Regex.IsMatch(lower, @"executionpolicy\s+bypass|-ep\s+bypass|-nop\b|-w\s+hidden|windowstyle\s+hidden", RegexOptions.IgnoreCase);
        bool persistence = Regex.IsMatch(lower, @"currentversion\\run|register-scheduledtask|schtasks(\.exe)?\s+/create|startup\\programs\\startup|__eventfilter|filtertoconsumerbinding", RegexOptions.IgnoreCase);
        bool disablesSecurity = Regex.IsMatch(lower, @"set-mppreference|disableantispyware|disablebehaviormonitoring|realtimeprotection|windefend|securityhealthservice", RegexOptions.IgnoreCase);
        bool writesBinary = Regex.IsMatch(lower, @"writeallbytes|adodb\.stream|certutil(\.exe)?[^\r\n]+-decode|frombase64string[^\r\n]+set-content", RegexOptions.IgnoreCase);
        bool lolbas = Regex.IsMatch(lower, @"\b(mshta|rundll32|regsvr32|wmic|certutil|bitsadmin|msiexec|installutil|msbuild|schtasks|powershell|wscript|cscript)(\.exe)?\b", RegexOptions.IgnoreCase);
        bool obfuscation = Regex.IsMatch(lower, @"\[char\]\d+|invoke-obfuscation|(\.replace|\.split|join\s*\()[^\r\n]{0,160}(powershell|wscript|mshta|http)|[a-z0-9+/]{500,}={0,2}", RegexOptions.IgnoreCase);

        if (encoded) result.Add("Script", "PowerShell EncodedCommand ou FromBase64String", javascriptLike ? 2 : 5, EvidenceStrength.High);
        if (longBase64 && (encoded || dynamicExec || lolbas || persistence)) result.Add("Script", "Base64 longo combinado com execução/persistência", 2, EvidenceStrength.Medium);
        if (dynamicExec) result.Add("Script", "Execução dinâmica ou download em script", javascriptLike ? 2 : 4, EvidenceStrength.Medium);
        if (downloadPayload) result.Add("Script", "Padrão download-and-execute", 4, EvidenceStrength.High);
        if (bypass) result.Add("Script", "Execução oculta ou bypass de política", javascriptLike ? 1 : 3, EvidenceStrength.Medium);
        if (persistence) result.Add("Persistence", "Script tenta criar persistência", 4, EvidenceStrength.Medium);
        if (disablesSecurity) result.Add("Script", "Script tenta alterar ou desativar proteção de segurança", 5, EvidenceStrength.High);
        if (writesBinary) result.Add("Script", "Script grava binário ou payload decodificado em disco", 4, EvidenceStrength.Medium);
        if (lolbas) result.Add("Script", "Uso de binário Windows sensível (LOLBAS)", javascriptLike ? 1 : 2, EvidenceStrength.Low);
        if (obfuscation) result.Add("Script", "Ofuscação por concatenação, replace/split/join, char codes ou blob codificado", javascriptLike ? 1 : 2, EvidenceStrength.Medium);

        return result;
    }

    private static string NormalizeScript(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (!CommentLine.IsMatch(line)) sb.AppendLine(line);
        }
        return sb.ToString();
    }
}

public static class PeAnalyzer
{
    public static AnalysisResult Analyze(string path) => DataVanger.Detection.PE.PeAnalyzer.Analyze(path);
}
public static class DocumentAnalyzer
{
    private static readonly HashSet<string> OfficeZipExt = new(StringComparer.OrdinalIgnoreCase)
        { ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".xlam" };

    public static AnalysisResult Analyze(string path)
    {
        string ext = Path.GetExtension(path);
        if (OfficeZipExt.Contains(ext)) return AnalyzeOfficeOpenXml(path);
        if (ext.Equals(".pdf", StringComparison.OrdinalIgnoreCase)) return AnalyzePdf(path);
        return new AnalysisResult();
    }

    private static AnalysisResult AnalyzeOfficeOpenXml(string path)
    {
        var result = new AnalysisResult();
        try
        {
            using var archive = ZipFile.OpenRead(path);
            foreach (var entry in archive.Entries.Take(1000))
            {
                string name = entry.FullName.Replace('/', '\\');
                string lower = name.ToLowerInvariant();
                if (lower.EndsWith("vbaproject.bin"))
                    result.Add("Document", "Documento Office contem projeto VBA/macro", 3, EvidenceStrength.Medium);
                if (lower.Contains("embeddings/"))
                    result.Add("Document", "Documento Office contem objeto OLE ou arquivo embutido", 2, EvidenceStrength.Low);
                if (lower.EndsWith(".rels") && entry.Length > 0 && entry.Length < 512 * 1024)
                {
                    string rel = ReadEntryText(entry).ToLowerInvariant();
                    if (rel.Contains("targetmode=\"external\"") &&
                        (rel.Contains("http://") || rel.Contains("https://") || rel.Contains("file://") || rel.Contains("\\\\")))
                        result.Add("Document", "Documento Office possui relacionamento externo remoto/local", 4, EvidenceStrength.Medium);
                }
                if ((lower.EndsWith(".xml") || lower.EndsWith(".bin")) && entry.Length > 0 && entry.Length < 512 * 1024)
                {
                    string text = ReadEntryText(entry).ToLowerInvariant();
                    if (Regex.IsMatch(text, @"auto(open|_open)|document_open|workbook_open|wscript\.shell|powershell|cmd\.exe", RegexOptions.IgnoreCase))
                        result.Add("Document", "Documento Office contem autoexec ou chamada a shell/script", 5, EvidenceStrength.High);
                    if (Regex.IsMatch(text, @"[a-z0-9+/]{500,}={0,2}", RegexOptions.IgnoreCase))
                        result.Add("Document", "Documento Office contem blob Base64 longo", 1, EvidenceStrength.Low);
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed/unreadable Office document - return collected evidence unchanged; fatal CLR exceptions are not swallowed.
        }
        return Deduplicate(result);
    }

    private static AnalysisResult AnalyzePdf(string path)
    {
        var result = new AnalysisResult();
        try
        {
            using var fs = File.OpenRead(path);
            var buffer = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
            int read = fs.Read(buffer, 0, buffer.Length);
            string text = Encoding.ASCII.GetString(buffer, 0, read).ToLowerInvariant();
            if (text.Contains("/javascript") || text.Contains("/js")) result.Add("Document", "PDF contem JavaScript embutido", 4, EvidenceStrength.Medium);
            if (text.Contains("/openaction")) result.Add("Document", "PDF contem OpenAction", 3, EvidenceStrength.Medium);
            if (text.Contains("/launch")) result.Add("Document", "PDF contem acao Launch", 5, EvidenceStrength.High);
            if (text.Contains("/embeddedfile")) result.Add("Document", "PDF contem arquivo embutido", 3, EvidenceStrength.Medium);
            if (Regex.IsMatch(text, @"https?://[^\s<>()]{8,}", RegexOptions.IgnoreCase)) result.Add("Document", "PDF contem URL externa", 1, EvidenceStrength.Low);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Malformed/unreadable PDF - return collected evidence unchanged; fatal CLR exceptions are not swallowed.
        }
        return result;
    }

    private static string ReadEntryText(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static AnalysisResult Deduplicate(AnalysisResult result)
    {
        var clean = new AnalysisResult();
        foreach (var e in result.Evidence.GroupBy(e => e.Description, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
            clean.Evidence.Add(e);
        return clean;
    }
}

/// <summary>
/// Backwards-compatible facade kept for callers that still depend on the
/// v3.x static analyzer. New code should use
/// <see cref="DataVanger.BrowserIntelligence.BrowserExtensionIntelligence"/>
/// which gives browser-context, manifest, bundle and trust analysis.
/// </summary>
public static class BrowserExtensionAnalyzer
{
    public static AnalysisResult AnalyzeManifest(string manifestPath) =>
        DataVanger.BrowserIntelligence.BrowserExtensionIntelligence.AnalyzeManifest(manifestPath);
}

public sealed class LocalReputationDatabase
{
    private readonly string _path;
    private readonly Dictionary<string, LocalReputationEntry> _entries;
    private readonly object _sync = new();

    public LocalReputationDatabase(string path)
    {
        _path = path;
        _entries = Load(path);
    }

    public LocalReputationEntry? Get(string hash) => TryGet(hash);

    public void ObserveFile(string sha256, string path, long sizeKB, DateTime lastWriteUtc, string signatureStatus = "", string publisher = "")
    {
        if (string.IsNullOrWhiteSpace(sha256)) return;
        string hash = sha256.Trim().ToUpperInvariant();
        lock (_sync)
        {
            if (!_entries.TryGetValue(hash, out var entry))
            {
                entry = new LocalReputationEntry
                {
                    SHA256 = hash,
                    FirstSeenUtc = DateTime.UtcNow
                };
                _entries[hash] = entry;
            }
            entry.SchemaVersion = LocalReputationEntry.CurrentSchemaVersion;
            entry.LastSeenUtc = DateTime.UtcNow;
            entry.SeenCount = Math.Max(0, entry.SeenCount) + 1;
            entry.ObservedPath = path;
            if (!string.IsNullOrWhiteSpace(path)
                && !entry.PathsSeen.Contains(path, StringComparer.OrdinalIgnoreCase)
                && entry.PathsSeen.Count < 32)
            {
                entry.PathsSeen.Add(path);
            }
            entry.FileSizeKB = sizeKB;
            entry.LastWriteTimeUtc = lastWriteUtc.ToUniversalTime();
            if (!string.IsNullOrWhiteSpace(signatureStatus)) entry.SignatureStatus = signatureStatus;
            if (!string.IsNullOrWhiteSpace(publisher)) entry.Publisher = publisher;
        }
    }
    public void Observe(ScanFinding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.SHA256)) return;
        string hash = finding.SHA256.Trim().ToUpperInvariant();
        lock (_sync)
        {
            if (!_entries.TryGetValue(hash, out var entry))
            {
                entry = new LocalReputationEntry
                {
                    SHA256 = hash,
                    FirstSeenUtc = DateTime.UtcNow
                };
                _entries[hash] = entry;
            }

            entry.SchemaVersion = LocalReputationEntry.CurrentSchemaVersion;
            entry.LastSeenUtc = DateTime.UtcNow;
            entry.SeenCount = Math.Max(0, entry.SeenCount) + 1;
            entry.ObservedPath = finding.Path;
            if (!string.IsNullOrWhiteSpace(finding.Path)
                && !entry.PathsSeen.Contains(finding.Path, StringComparer.OrdinalIgnoreCase)
                && entry.PathsSeen.Count < 32)
            {
                entry.PathsSeen.Add(finding.Path);
            }
            entry.FileSizeKB = finding.SizeKB;
            entry.LastWriteTimeUtc = finding.LastWrite.ToUniversalTime();
            entry.SignatureStatus = finding.ReputationSignerStatus == "Unknown"
                ? (finding.IsSigned ? "Signed" : "Unsigned")
                : finding.ReputationSignerStatus;
            entry.Publisher = finding.Publisher;
            entry.PreviousScore = finding.Score;
            entry.StaticScore = finding.Score - finding.ReputationScoreDelta;
            entry.PreviousClassification = finding.RiskLabel;
            entry.UserDecision = string.IsNullOrWhiteSpace(finding.ReputationUserDecision) ? entry.UserDecision : finding.ReputationUserDecision;
            entry.WhitelistStatus = finding.ReputationState is ReputationTrustState.KnownGood or ReputationTrustState.LikelyGood;
            entry.BlocklistStatus = finding.IsBlacklisted;
            entry.QuarantineStatus = finding.WasQuarantined;
            entry.TrustState = finding.ReputationState.ToString();
            entry.ReputationScore = finding.ReputationScore;
            entry.BehavioralScore = 0;
            entry.EvidenceSummary = finding.EvidenceSummary;
            entry.Notes = finding.ReputationReasons.Count == 0 ? entry.Notes : string.Join("; ", finding.ReputationReasons);
        }
    }

    public void MarkUserDecision(string sha256, ReputationUserDecision decision, string? note = null)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return;
        string hash = sha256.Trim().ToUpperInvariant();
        lock (_sync)
        {
            if (!_entries.TryGetValue(hash, out var entry))
            {
                entry = new LocalReputationEntry
                {
                    SHA256 = hash,
                    FirstSeenUtc = DateTime.UtcNow
                };
                _entries[hash] = entry;
            }
            entry.SchemaVersion = LocalReputationEntry.CurrentSchemaVersion;
            entry.UserDecision = decision.ToString();
            entry.LastSeenUtc = DateTime.UtcNow;
            if (decision == ReputationUserDecision.Allowed) entry.WhitelistStatus = true;
            if (decision is ReputationUserDecision.Blocked or ReputationUserDecision.Quarantined) entry.BlocklistStatus = true;
            if (!string.IsNullOrWhiteSpace(note)) entry.Notes = note;
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var opts = new JsonSerializerOptions { WriteIndented = true };
            List<LocalReputationEntry> snapshot;
            lock (_sync)
            {
                snapshot = _entries.Values
                    .OrderByDescending(e => e.LastSeenUtc)
                    .Take(250_000)
                    .ToList();
            }

            string temp = _path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(snapshot, opts), Encoding.UTF8);
            if (File.Exists(_path))
            {
                string backup = _path + ".bak";
                try { File.Replace(temp, _path, backup, ignoreMetadataErrors: true); }
                catch (System.Exception) { File.Copy(temp, _path, overwrite: true); TryDelete(temp); }
            }
            else
            {
                File.Move(temp, _path);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Reputation store failed to persist - make the failure observable but do not abort the caller.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to persist reputation store '{_path}': {ex.Message}");
        }
    }

    private LocalReputationEntry? TryGet(string hash)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(hash, out var entry) ? entry : null;
        }
    }

    private static Dictionary<string, LocalReputationEntry> Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return new Dictionary<string, LocalReputationEntry>(StringComparer.OrdinalIgnoreCase);
            var list = JsonSerializer.Deserialize<List<LocalReputationEntry>>(File.ReadAllText(path)) ?? new();
            return list.Where(e => !string.IsNullOrWhiteSpace(e.SHA256))
                .Select(Normalize)
                .GroupBy(e => e.SHA256, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(e => e.LastSeenUtc).First(), StringComparer.OrdinalIgnoreCase);
        }
        catch (System.Exception)
        {
            TryBackupCorrupt(path);
            return new Dictionary<string, LocalReputationEntry>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static LocalReputationEntry Normalize(LocalReputationEntry entry)
    {
        entry.SchemaVersion = Math.Max(1, entry.SchemaVersion);
        entry.SHA256 = entry.SHA256.Trim().ToUpperInvariant();
        if (entry.FirstSeenUtc == default) entry.FirstSeenUtc = entry.LastSeenUtc == default ? DateTime.UtcNow : entry.LastSeenUtc;
        if (entry.LastSeenUtc == default) entry.LastSeenUtc = entry.FirstSeenUtc;
        if (entry.SeenCount <= 0) entry.SeenCount = 1;
        if (!string.IsNullOrWhiteSpace(entry.ObservedPath)
            && !entry.PathsSeen.Contains(entry.ObservedPath, StringComparer.OrdinalIgnoreCase))
            entry.PathsSeen.Add(entry.ObservedPath);
        return entry;
    }

    private static void TryBackupCorrupt(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            string backup = path + ".corrupt." + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            File.Copy(path, backup, overwrite: false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Best-effort backup of a corrupt store - make observable but continue.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to back up corrupt reputation store '{path}': {ex.Message}");
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Best-effort temp delete - make observable but continue.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to delete temp file '{path}': {ex.Message}");
        }
    }
}

public sealed class LocalReputationEntry
{
    public const int CurrentSchemaVersion = 2;
    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public string SHA256 { get; set; } = "";
    public string ObservedPath { get; set; } = "";
    public List<string> PathsSeen { get; set; } = new();
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int SeenCount { get; set; }
    public long SizeKB
    {
        get => FileSizeKB;
        set => FileSizeKB = value;
    }
    public long FileSizeKB { get; set; }
    public DateTime LastWriteTimeUtc { get; set; }
    public string SignatureStatus { get; set; } = "";
    public string Publisher { get; set; } = "";
    public int PreviousScore { get; set; }
    public int StaticScore { get; set; }
    public int BehavioralScore { get; set; }
    public string PreviousClassification { get; set; } = "";
    public string UserDecision { get; set; } = "";
    public bool WhitelistStatus { get; set; }
    public bool BlocklistStatus { get; set; }
    public bool QuarantineStatus { get; set; }
    public string TrustState { get; set; } = "Unknown";
    public int ReputationScore { get; set; }
    public string Notes { get; set; } = "";
    public string EvidenceSummary { get; set; } = "";
}
