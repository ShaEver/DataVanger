using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DataVanger.Core;

public sealed class SignatureDatabase
{
    public HashSet<string> KnownMalicious { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> KnownSafe { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> UserBlacklist { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> UserWhitelist { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int TotalHashes => KnownMalicious.Count + KnownSafe.Count + UserBlacklist.Count + UserWhitelist.Count;

    public bool IsKnownMalicious(string sha256) =>
        KnownMalicious.Contains(sha256) || UserBlacklist.Contains(sha256);

    public bool IsKnownSafe(string sha256) =>
        !IsKnownMalicious(sha256) && (KnownSafe.Contains(sha256) || UserWhitelist.Contains(sha256));

    public static SignatureDatabase Load(string signatureRoot, string? legacyBlacklistPath = null, string? legacyWhitelistPath = null)
    {
        Directory.CreateDirectory(signatureRoot);

        var db = new SignatureDatabase();
        string knownMaliciousPath = Path.Combine(signatureRoot, "known_malicious_sha256.txt");
        string knownSafePath      = Path.Combine(signatureRoot, "known_safe_sha256.txt");
        string userBlacklistPath  = Path.Combine(signatureRoot, "user_blacklist_sha256.txt");
        string userWhitelistPath  = Path.Combine(signatureRoot, "user_whitelist_sha256.txt");

        EnsureFile(knownMaliciousPath);
        EnsureFile(knownSafePath);
        EnsureFile(userBlacklistPath);
        EnsureFile(userWhitelistPath);

        LoadFile(knownMaliciousPath, db.KnownMalicious);
        LoadFile(knownSafePath, db.KnownSafe);
        LoadFile(userBlacklistPath, db.UserBlacklist);
        LoadFile(userWhitelistPath, db.UserWhitelist);

        // Compatibilidade com os arquivos antigos da v1.0.
        if (!string.IsNullOrWhiteSpace(legacyBlacklistPath)) LoadFile(legacyBlacklistPath, db.UserBlacklist);
        if (!string.IsNullOrWhiteSpace(legacyWhitelistPath)) LoadFile(legacyWhitelistPath, db.UserWhitelist);

        return db;
    }

    private static void EnsureFile(string path)
    {
        if (!File.Exists(path)) File.WriteAllText(path, "");
    }

    private static void LoadFile(string path, HashSet<string> destination)
    {
        try
        {
            if (!File.Exists(path)) return;
            foreach (var line in File.ReadLines(path))
            {
                var clean = line.Split(new[] { '#' }, 2)[0].Split(new[] { ';' }, 2)[0].Trim();
                if (string.IsNullOrWhiteSpace(clean)) continue;
                var h = clean.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim().ToUpperInvariant() ?? "";
                if (h.Length == 64 && h.All(Uri.IsHexDigit))
                    destination.Add(h);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException
                                   and not StackOverflowException
                                   and not AccessViolationException
                                   and not System.Threading.ThreadAbortException)
        {
            // Signature list partially loaded - record the failure so a degraded database is observable, but continue.
            System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to load signature file '{path}': {ex.Message}");
        }
    }
}
