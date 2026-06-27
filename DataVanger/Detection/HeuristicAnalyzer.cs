using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// File-path, name, attribute and lightweight content heuristics.
///
/// Extracted from <c>ScanEngine.ComputeHeuristics</c> so the same logic can
/// be tested in isolation and re-used by both the bulk scan engine and
/// realtime triggers.
///
/// The output is an <see cref="AnalysisResult"/>: only ScoreDelta and
/// Evidence — never a verdict. All evidence produced here is heuristic and
/// must never confirm malware.
/// </summary>
public static class HeuristicAnalyzer
{
    private static readonly HashSet<string> DownloadExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".msi", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".wsf", ".ps1", ".psm1", ".lnk", ".iso", ".img", ".hta" };

    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
        { ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta" };

    private static readonly HashSet<string> ExeExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com" };

    private static readonly HashSet<string> EntropyExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".dll", ".sys" };

    private static readonly HashSet<string> RecentExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".msi", ".hta", ".dll" };

    // Critical Windows process names. A binary with one of these names outside
    // System32/SysWOW64 is a strong masquerading signal.
    private static readonly HashSet<string> SystemExecutableNames = new(StringComparer.OrdinalIgnoreCase)
        { "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
          "smss.exe", "wininit.exe", "spoolsv.exe", "dwm.exe", "taskhostw.exe", "explorer.exe", "rundll32.exe" };

    // FASE 3 — header-sample size shared by the entropy and appended-PE-data
    // heuristics. Both only inspect the first few KB, so a single 4 KB read
    // feeds both checks instead of opening the file twice.
    private const int ContentSampleSize = 4096;

    public static AnalysisResult Analyze(ScanTarget target, ScanContext context)
    {
        var result = new AnalysisResult();
        var file = target.File;
        string name = target.FileNameLower;
        string full = target.FullPathLower;
        string ext = target.Extension;

        bool benignScriptContainer = PathTaxonomy.IsKnownBenignScriptContainer(full);
        bool userWritable = PathTaxonomy.IsUserWritableRiskPath(full);
        bool protectedWindows = PathTaxonomy.IsProtectedWindowsPath(full);
        bool microsoftPath = PathTaxonomy.IsMicrosoftProductPath(full);
        bool deep = context.Deep;

        if (Regex.IsMatch(name, @"\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|txt)\.(exe|scr|com|bat|cmd)$"))
            result.Add("Heuristic", "Dupla extensão disfarçada", 8, EvidenceStrength.High);

        if (full.Contains("\\downloads\\") && DownloadExt.Contains(ext))
            result.Add("Heuristic", "Executável/script em Downloads",
                ScriptExt.Contains(ext) ? 2 : 4, EvidenceStrength.Low);

        if (full.Contains("\\temp\\") && new[] { ".exe", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta" }.Contains(ext))
            result.Add("Heuristic", "Executável/script em Temp",
                PathTaxonomy.IsTempRandomScript(full, name, ext) ? 3 : (ScriptExt.Contains(ext) ? 2 : 4),
                EvidenceStrength.Low);

        if (full.Contains("\\appdata\\") && new[] { ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".dll" }.Contains(ext)
            && !benignScriptContainer)
            result.Add("Heuristic", "Executável/script em AppData",
                ScriptExt.Contains(ext) ? 1 : 2, EvidenceStrength.Low);

        try
        {
            if ((file.Attributes & FileAttributes.Hidden) != 0)
                result.Add("Heuristic", "Arquivo oculto", 1, EvidenceStrength.Low);
            if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                result.Add("Heuristic", "Link simbólico/reparse point", 1, EvidenceStrength.Low);
        }
        catch (UnauthorizedAccessException)
        {
            // Protected file - skip attribute heuristic and preserve scan flow.
        }
        catch (IOException)
        {
            // Locked/unreadable file - skip attribute heuristic and preserve scan flow.
        }

        if (Regex.IsMatch(name, @"(^|[\W_])(crack|keygen|activator|patch_by|bypass|nulled|warez)([\W_]|$)"))
            result.Add("Heuristic", "Nome crítico de ameaça", 4, EvidenceStrength.Medium);
        else if (Regex.IsMatch(name, @"(^|[\W_])(free|bonus|setup)([\W_]|$)|(^|[\W_])patch([\W_]|$)") && userWritable)
            result.Add("Heuristic", "Nome potencialmente enganoso", 1, EvidenceStrength.Low);

        if (ext == ".lnk" && full.Contains("\\downloads\\"))
            result.Add("Heuristic", "Atalho .lnk em Downloads", 3, EvidenceStrength.Medium);

        if (ExeExt.Contains(ext) && file.Length < 256 * 1024 && userWritable)
            result.Add("Heuristic", "Executável pequeno em local gravável pelo usuário", 1, EvidenceStrength.Low);

        if (EntropyExt.Contains(ext))
        {
            // FASE 3 — entropy and appended-PE-data both inspect the file header.
            // Read it once into a pooled buffer instead of opening the file twice.
            byte[] sample = ArrayPool<byte>.Shared.Rent(ContentSampleSize);
            try
            {
                int read = ReadHeaderSample(target.FullPath, sample, ContentSampleSize);

                double e = ByteEntropy(sample, read);
                if (e > 7.2 && userWritable)
                    result.Add("Heuristic", $"Entropia alta ({e:F4} b/B - possível packing)", 2, EvidenceStrength.Medium);

                if (ExeExt.Contains(ext) && userWritable && HasAppendedData(sample, read, file.Length))
                    result.Add("Heuristic", "Dados anexados ao PE em local gravável", 1, EvidenceStrength.Low);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(sample, clearArray: false);
            }
        }

        if (RecentExt.Contains(ext) && userWritable)
        {
            try
            {
                double hours = (DateTime.Now - file.CreationTime).TotalHours;
                if (hours < 48)
                    result.Add("Heuristic", $"Arquivo recente em local gravável (criado há {hours:F1}h)", 1, EvidenceStrength.Low);
            }
            catch (UnauthorizedAccessException)
            {
                // Protected file - skip recency heuristic and preserve scan flow.
            }
            catch (IOException)
            {
                // Locked/unreadable file - skip recency heuristic and preserve scan flow.
            }
        }

        if (ext is ".dll" or ".sys")
        {
            bool isSystem = protectedWindows;
            if (!isSystem && (userWritable || !PathTaxonomy.IsProgramVendorPath(full)))
                result.Add("Heuristic",
                    ext == ".sys" ? "Driver fora de pasta de sistema" : "DLL fora de pasta de sistema",
                    ext == ".sys" ? 4 : 2, EvidenceStrength.Medium);
        }

        if (ExeExt.Contains(ext) && SystemExecutableNames.Contains(name) && !protectedWindows)
            result.Add("Heuristic",
                $"Nome de processo de sistema ({name}) fora de System32/SysWOW64 - possível mascaramento",
                7, EvidenceStrength.High);

        // Regex is checked before the file read so the (up to 256 KB) icon scan
        // only runs for the rare double-extension names that could be masquerading.
        if (ExeExt.Contains(ext) &&
            Regex.IsMatch(name, @"\.(pdf|jpg|jpeg|png|doc|docx|txt)\.(exe|scr|com)$") &&
            HasFakeIcon(target.FullPath))
            result.Add("Heuristic", "Executável tentando se passar por documento/imagem", 3, EvidenceStrength.High);

        if (deep && HasAlternateDataStreams(target.FullPath) && userWritable)
            result.Add("Heuristic", "Mark-of-the-Web/ADS em arquivo de local gravável", 1, EvidenceStrength.Low);

        if (context.RunningProcessPaths.Contains(full) && userWritable && !benignScriptContainer && !protectedWindows)
            result.Add("Heuristic", "Processo em execução a partir de local gravável pelo usuário", 2, EvidenceStrength.Medium);

        return result;
    }

    /// <summary>
    /// Applies the well-known-vendor / protected-Windows safety nets.
    /// When the file lives in a protected/official path AND no strong
    /// behavior was found, all heuristic evidence is suppressed to prevent
    /// false positives. Returns the (possibly zero) score delta after suppression.
    /// </summary>
    public static int ApplyTrustedPathSuppression(ScanTarget target, AnalysisResult heuristicResult)
    {
        if (heuristicResult.Evidence.Count == 0) return 0;
        string full = target.FullPathLower;
        bool protectedWindows = PathTaxonomy.IsProtectedWindowsPath(full);
        bool microsoftPath = PathTaxonomy.IsMicrosoftProductPath(full);
        bool userWritable = PathTaxonomy.IsUserWritableRiskPath(full);
        bool benignContainer = PathTaxonomy.IsKnownBenignScriptContainer(full);

        bool strongBehavior = HasStrongMalwareBehavior(heuristicResult.Evidence);

        if ((protectedWindows || (microsoftPath && !userWritable)) && !strongBehavior)
        {
            heuristicResult.Evidence.Clear();
            heuristicResult.Evidence.Add(new Evidence
            {
                Category = "Heuristic",
                Description = "Caminho protegido/oficial; heurísticas isoladas ignoradas para evitar falso positivo",
                ScoreDelta = 0,
                Strength = EvidenceStrength.Info,
            });
            return 0;
        }

        if (benignContainer && !PathTaxonomy.IsTempRandomScript(full, target.FileNameLower, target.Extension) && !strongBehavior)
        {
            heuristicResult.Evidence.Clear();
            heuristicResult.Evidence.Add(new Evidence
            {
                Category = "Heuristic",
                Description = "Contexto de pacote/aplicativo conhecido; heurísticas isoladas ignoradas para evitar falso positivo",
                ScoreDelta = 0,
                Strength = EvidenceStrength.Info,
            });
            return 0;
        }

        return heuristicResult.Score;
    }

    private static bool HasStrongMalwareBehavior(IEnumerable<Evidence> evidence) =>
        evidence.Any(e =>
            e.CanConfirmMalware
            || e.Description.Contains("mascaramento", StringComparison.OrdinalIgnoreCase)
            || e.Description.Contains("dupla extensão", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// FASE 3 — reads up to <paramref name="maxBytes"/> from the start of a file
    /// into <paramref name="buffer"/>, using a sequential-scan hint so the OS can
    /// prefetch. Returns the number of bytes read (0 on any error). Callers must
    /// never inspect <paramref name="buffer"/> past the returned length, since the
    /// pooled buffer may contain stale bytes from a previous rent.
    /// </summary>
    private static int ReadHeaderSample(string path, byte[] buffer, int maxBytes)
    {
        try
        {
            using var fs = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                Options = FileOptions.SequentialScan,
                BufferSize = ContentSampleSize,
            });
            int want = (int)Math.Min(maxBytes, fs.Length);
            return want <= 0 ? 0 : fs.Read(buffer, 0, want);
        }
        catch (System.Exception) { return 0; }
    }

    private static double ByteEntropy(byte[] buf, int read)
    {
        if (read < 32) return 0.0;
        var freq = new int[256];
        for (int i = 0; i < read; i++) freq[buf[i]]++;
        double e = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / read;
            e -= p * Math.Log2(p);
        }
        return Math.Round(e, 4);
    }

    private static bool HasFakeIcon(string path)
    {
        int limit;
        try { limit = (int)Math.Min(new FileInfo(path).Length, 256 * 1024); }
        catch (System.Exception) { return false; }
        if (limit < 64) return false;

        byte[] buf = ArrayPool<byte>.Shared.Rent(limit);
        try
        {
            int read = ReadHeaderSample(path, buf, limit);
            if (read < 64) return false;
            int peOff = BitConverter.ToInt32(buf, 0x3C);
            if (peOff <= 0 || peOff + 2 >= read) return false;
            if (buf[peOff] != 0x50 || buf[peOff + 1] != 0x45) return false;
            for (int i = 0; i < read - 4; i++)
            {
                if (buf[i] == 0xFF && buf[i + 1] == 0xD8 && buf[i + 2] == 0xFF) return true;
                if (buf[i] == 0x89 && buf[i + 1] == 0x50 && buf[i + 2] == 0x4E && buf[i + 3] == 0x47) return true;
                if (buf[i] == 0x42 && buf[i + 1] == 0x4D) return true;
            }
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf, clearArray: false);
        }
    }

    private static bool HasAppendedData(byte[] header, int read, long fileLength)
    {
        if (fileLength < 64 || read < 64) return false;
        int peOff = BitConverter.ToInt32(header, 0x3C);
        if (peOff <= 0 || peOff + 24 >= read) return false;
        if (header[peOff] != 0x50 || header[peOff + 1] != 0x45) return false;
        int optOff = peOff + 24;
        // Precise bounds: only read the SizeOfImage field if it lies within the
        // bytes actually read (the pooled buffer may hold stale bytes beyond `read`).
        if (optOff + 2 > read) return false;
        ushort magic = BitConverter.ToUInt16(header, optOff);
        int soimOff = magic == 0x20B ? 52 : 56;
        if (optOff + soimOff + 4 > read) return false;
        int sizeOfImage = BitConverter.ToInt32(header, optOff + soimOff);
        return sizeOfImage > 0 && fileLength > sizeOfImage + 512;
    }

    private static bool HasAlternateDataStreams(string path)
    {
        try { return File.Exists(path + ":Zone.Identifier"); }
        catch (System.Exception) { return false; }
    }
}
