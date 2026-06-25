using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DataVanger.Core;
using DataVanger.Core.Domain;

namespace DataVanger.Detection;

/// <summary>
/// ZIP / Office-container archive heuristics.
///
/// Extracted from the legacy <c>ScanEngine.AnalyzeArchive</c> so the same
/// rules can be reused by the archive detection module and by future tests.
/// Output is an <see cref="AnalysisResult"/> — score deltas, not verdicts.
/// </summary>
public static class ArchiveAnalyzer
{
    private static readonly HashSet<string> DangerExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".msi", ".lnk", ".iso", ".img", ".dll", ".sys", ".hta" };

    private static readonly HashSet<string> ArchiveExt = new(StringComparer.OrdinalIgnoreCase)
        { ".zip", ".jar", ".war", ".ear", ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".xlam", ".xla", ".hta", ".chm" };

    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
        { ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".ps1", ".psm1", ".hta" };

    public static AnalysisResult Analyze(FileInfo file, int maxEntries)
    {
        var result = new AnalysisResult();
        try
        {
            int maxEntriesEffective = Math.Clamp(maxEntries, 50, 5000);
            using var archive = ZipFile.OpenRead(file.FullName);
            int inspected = 0;
            int executableEntries = 0;
            int suspiciousScripts = 0;
            bool doubleExtension = false;
            bool macroPayload = false;
            bool suspiciousName = false;
            bool nestedArchive = false;
            bool officeExternalRelationship = false;
            bool officeAutoExec = false;
            var scriptReasons = new List<string>();

            foreach (var entry in archive.Entries)
            {
                if (++inspected > maxEntriesEffective) break;
                string name = entry.FullName.Replace('/', '\\').ToLowerInvariant();
                string entryExt = Path.GetExtension(name);

                if (Regex.IsMatch(name, @"\.(pdf|jpg|jpeg|png|doc|docx|xls|xlsx|txt)\.(exe|scr|com|bat|cmd|js|vbs|ps1)$", RegexOptions.IgnoreCase))
                    doubleExtension = true;

                if (DangerExt.Contains(entryExt)) executableEntries++;
                if (ArchiveExt.Contains(entryExt)) nestedArchive = true;
                if (Regex.IsMatch(name, @"(^|[\\/_\W])(crack|keygen|activator|bypass|nulled|payload|dropper)([\\/_\W]|$)", RegexOptions.IgnoreCase))
                    suspiciousName = true;
                if (name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                    macroPayload = true;

                if (name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase) && entry.Length > 0 && entry.Length < 256 * 1024)
                {
                    try
                    {
                        string relText = ReadEntryUtf8(entry).ToLowerInvariant();
                        if (relText.Contains("targetmode=\"external\"") &&
                            (relText.Contains("http://") || relText.Contains("https://") || relText.Contains("file://") || relText.Contains("\\\\")))
                            officeExternalRelationship = true;
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException
                                               and not StackOverflowException
                                               and not AccessViolationException
                                               and not System.Threading.ThreadAbortException)
                    {
                        // Corrupt/unreadable archive entry - skip this entry's heuristic and continue; fatal CLR exceptions are not swallowed.
                    }
                }

                if ((name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)) &&
                    entry.Length > 0 && entry.Length < 512 * 1024)
                {
                    try
                    {
                        string xmlText = ReadEntryUtf8(entry).ToLowerInvariant();
                        if (xmlText.Contains("auto_open") || xmlText.Contains("document_open") || xmlText.Contains("workbook_open") ||
                            xmlText.Contains("wscript.shell") || xmlText.Contains("powershell") || xmlText.Contains("cmd.exe"))
                            officeAutoExec = true;
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException
                                               and not StackOverflowException
                                               and not AccessViolationException
                                               and not System.Threading.ThreadAbortException)
                    {
                        // Corrupt/unreadable archive entry - skip this entry's heuristic and continue; fatal CLR exceptions are not swallowed.
                    }
                }

                if (ScriptExt.Contains(entryExt) && entry.Length > 0 && entry.Length < 512 * 1024)
                {
                    try
                    {
                        string text = ReadEntryUtf8(entry);
                        var nested = ScriptAnalyzer.AnalyzeText(text, entryExt, benignContainer: false);
                        if (nested.HasHits)
                        {
                            suspiciousScripts++;
                            foreach (var ev in nested.Evidence.Take(2))
                                scriptReasons.Add($"Arquivo compactado contém script suspeito: {entry.FullName} ({ev.Description})");
                        }
                    }
                    catch (Exception ex) when (ex is not OutOfMemoryException
                                               and not StackOverflowException
                                               and not AccessViolationException
                                               and not System.Threading.ThreadAbortException)
                    {
                        // Corrupt/unreadable archive entry - skip this entry's heuristic and continue; fatal CLR exceptions are not swallowed.
                    }
                }
            }

            if (doubleExtension) result.Add("Archive", "Arquivo compactado contém dupla extensão executável", 8, EvidenceStrength.High);
            if (executableEntries >= 3) result.Add("Archive", $"Arquivo compactado contém {executableEntries} item(ns) executáveis/scripts", 3, EvidenceStrength.Medium);
            else if (executableEntries > 0 && suspiciousName) result.Add("Archive", "Arquivo compactado contém executável/script com nome crítico", 4, EvidenceStrength.High);
            if (suspiciousName) result.Add("Archive", "Arquivo compactado contém nome associado a crack/keygen/dropper", 2, EvidenceStrength.Medium);
            if (macroPayload && (file.Extension.Equals(".docm", StringComparison.OrdinalIgnoreCase)
                              || file.Extension.Equals(".xlsm", StringComparison.OrdinalIgnoreCase)
                              || file.Extension.Equals(".pptm", StringComparison.OrdinalIgnoreCase)))
                result.Add("Document", "Documento Office macro-enabled contém projeto VBA", 2, EvidenceStrength.Medium);
            if (nestedArchive) result.Add("Archive", "Arquivo compactado contém outro compactado/anexo interno", 1, EvidenceStrength.Low);
            if (officeExternalRelationship) result.Add("Document", "Documento Office contém relacionamento externo potencialmente perigoso", 4, EvidenceStrength.Medium);
            if (officeAutoExec) result.Add("Document", "Documento Office contém indícios de macro/execução automática", 5, EvidenceStrength.High);
            if (suspiciousScripts > 0)
            {
                int delta = Math.Min(6, suspiciousScripts * 3);
                foreach (var reason in scriptReasons.Distinct(StringComparer.OrdinalIgnoreCase).Take(3))
                    result.Add("Archive", reason, 0, EvidenceStrength.Medium);
                result.Add("Archive", $"Scripts suspeitos detectados dentro do compactado: {suspiciousScripts}", delta, EvidenceStrength.Medium);
            }
        }
        catch
        {
            // Corrupt/encrypted archive — leave result empty; engine will log resilience event.
        }
        return result;
    }

    private static string ReadEntryUtf8(ZipArchiveEntry entry)
    {
        using var stream = entry.Open();
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static bool IsArchiveExtension(string extension) => ArchiveExt.Contains(extension);
}
