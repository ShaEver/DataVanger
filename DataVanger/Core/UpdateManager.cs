using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace DataVanger.Core;

public static class UpdateManager
{
    public static async Task<bool> UpdateSignaturesAsync(string url, string destinationPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(url)) return false;

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            string content = await http.GetStringAsync(url);
            if (content.TrimStart().StartsWith("{", StringComparison.Ordinal))
            {
                var manifestOk = await TryUpdateFromManifestAsync(http, url, content, destinationPath);
                if (manifestOk) return true;
            }

            var validLines = content
                .Split('\n')
                .Select(x => x.Split(new[] { '#' }, 2)[0].Split(new[] { ';' }, 2)[0].Trim())
                .Select(x => x.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim().ToUpperInvariant() ?? "")
                .Where(x => x.Length == 64 && x.All(Uri.IsHexDigit))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (validLines.Count < 1)
                return false;

            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);

            if (File.Exists(destinationPath))
                File.Copy(destinationPath, destinationPath + ".bak", overwrite: true);

            await File.WriteAllLinesAsync(destinationPath, validLines);
            await File.WriteAllTextAsync(destinationPath + ".lastupdate.txt", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> TryUpdateFromManifestAsync(HttpClient http, string manifestUrl, string manifestJson, string destinationPath)
    {
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            var root = doc.RootElement;
            if (!root.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Array) return false;
            var blacklist = files.EnumerateArray().FirstOrDefault(f =>
                f.TryGetProperty("name", out var n) &&
                n.GetString()?.Contains("blacklist", StringComparison.OrdinalIgnoreCase) == true);
            if (blacklist.ValueKind == JsonValueKind.Undefined) return false;
            string? relativeUrl = blacklist.TryGetProperty("url", out var urlEl) ? urlEl.GetString() : null;
            string? sha256 = blacklist.TryGetProperty("sha256", out var shaEl) ? shaEl.GetString() : null;
            if (string.IsNullOrWhiteSpace(relativeUrl) || string.IsNullOrWhiteSpace(sha256)) return false;

            var baseUri = new Uri(manifestUrl);
            var fileUri = new Uri(baseUri, relativeUrl);
            byte[] bytes = await http.GetByteArrayAsync(fileUri);
            string actual = Convert.ToHexString(SHA256.HashData(bytes));
            if (!actual.Equals(sha256.Trim(), StringComparison.OrdinalIgnoreCase)) return false;

            string temp = destinationPath + ".download";
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            await File.WriteAllBytesAsync(temp, bytes);
            string text = await File.ReadAllTextAsync(temp);
            var validLines = ParseHashLines(text).ToList();
            if (validLines.Count == 0) return false;
            if (File.Exists(destinationPath)) File.Copy(destinationPath, destinationPath + ".bak", overwrite: true);
            await File.WriteAllLinesAsync(destinationPath, validLines);
            await File.WriteAllTextAsync(destinationPath + ".manifest.json", manifestJson);
            try { File.Delete(temp); }
            catch (Exception ex) when (ex is not OutOfMemoryException
                                       and not StackOverflowException
                                       and not AccessViolationException
                                       and not System.Threading.ThreadAbortException)
            {
                // Leftover temp file is harmless - make the cleanup failure observable but continue.
                System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to delete update temp file '{temp}': {ex.Message}");
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> ParseHashLines(string content) =>
        content
            .Split('\n')
            .Select(x => x.Split(new[] { '#' }, 2)[0].Split(new[] { ';' }, 2)[0].Trim())
            .Select(x => x.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim().ToUpperInvariant() ?? "")
            .Where(x => x.Length == 64 && x.All(Uri.IsHexDigit))
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
