using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataVanger.Core;

public class QuarantineManager
{
    private readonly string _quarantineRoot;
    private readonly string _indexPath;

    public QuarantineManager(string quarantineRoot, string indexPath)
    {
        _quarantineRoot = quarantineRoot;
        _indexPath      = indexPath;
        Directory.CreateDirectory(quarantineRoot);
    }

    // ── Index I/O ─────────────────────────────────────────────────────────────
    public Dictionary<string, QuarantineEntry> LoadIndex()
    {
        try
        {
            if (!File.Exists(_indexPath)) return new();
            var raw = File.ReadAllText(_indexPath);
            return JsonSerializer.Deserialize<Dictionary<string, QuarantineEntry>>(raw) ?? new();
        }
        catch { return new(); }
    }

    private void SaveIndex(Dictionary<string, QuarantineEntry> index)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_indexPath)!);
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(_indexPath, JsonSerializer.Serialize(index, opts));
    }

    // ── Quarantine ────────────────────────────────────────────────────────────
    /// <summary>Encrypts file into quarantine and removes the original. Returns the quarantine ID on success, null on failure.</summary>
    public string? Quarantine(ScanFinding finding)
    {
        if (!File.Exists(finding.Path)) return null;

        string id  = !string.IsNullOrWhiteSpace(finding.SHA256) ? finding.SHA256! : Guid.NewGuid().ToString("N");
        string dst = Path.Combine(_quarantineRoot, id + ".quarantine");

        try
        {
            var fi = new FileInfo(finding.Path);
            EncryptFile(finding.Path, dst);
            File.Delete(finding.Path);

            var index = LoadIndex();
            index[id] = new QuarantineEntry
            {
                Id             = id,
                OriginalPath   = finding.Path,
                QuarantinePath = dst,
                QuarantinedAt  = DateTime.Now,
                Score          = finding.Score,
                Reasons        = finding.Reasons,
                SHA256         = finding.SHA256,
                IsEncrypted    = true,
                OriginalSize   = fi.Length,
            };
            SaveIndex(index);
            return id;
        }
        catch
        {
            try { if (File.Exists(dst)) File.Delete(dst); }
            catch (Exception cleanupEx) when (cleanupEx is not OutOfMemoryException
                                              and not StackOverflowException
                                              and not AccessViolationException
                                              and not System.Threading.ThreadAbortException)
            {
                // Best-effort removal of a partial quarantine artifact - make observable but preserve the null return.
                System.Diagnostics.Debug.WriteLine($"[DataVanger] Failed to remove partial quarantine file '{dst}': {cleanupEx.Message}");
            }
            return null;
        }
    }

    // ── Restore ───────────────────────────────────────────────────────────────
    /// <summary>Restores a quarantined file. Returns true on success.</summary>
    public bool Restore(string id)
    {
        var index = LoadIndex();
        if (!index.TryGetValue(id, out var entry)) return false;

        string src = !string.IsNullOrWhiteSpace(entry.QuarantinePath)
            ? entry.QuarantinePath
            : Path.Combine(_quarantineRoot, id + ".quarantine");
        if (!File.Exists(src)) return false;

        try
        {
            var destDir = Path.GetDirectoryName(entry.OriginalPath);
            if (destDir != null) Directory.CreateDirectory(destDir);

            if (entry.IsEncrypted)
            {
                DecryptFile(src, entry.OriginalPath);
                File.Delete(src);
            }
            else
            {
                File.Move(src, entry.OriginalPath, overwrite: true);
            }

            index.Remove(id);
            SaveIndex(index);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── List ──────────────────────────────────────────────────────────────────
    public IReadOnlyDictionary<string, QuarantineEntry> List() => LoadIndex();

    // ── Basic encrypted quarantine storage ────────────────────────────────────
    // Observação: isto torna o arquivo inutilizável fora do DataVanger. Para produção,
    // idealmente substituir por DPAPI/keystore e política de rotação de chave.
    private static byte[] GetLocalKey()
    {
        string material = "DataVanger.Local.Quarantine.v1|" +
            Environment.UserName + "|" +
            Environment.MachineName + "|" +
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        return SHA256.HashData(Encoding.UTF8.GetBytes(material));
    }

    private static void EncryptFile(string sourcePath, string destinationPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = GetLocalKey();
        aes.GenerateIV();

        using var input = File.OpenRead(sourcePath);
        using var output = File.Create(destinationPath);
        output.Write(aes.IV, 0, aes.IV.Length);

        using var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
        input.CopyTo(crypto);
    }

    private static void DecryptFile(string sourcePath, string destinationPath)
    {
        using var input = File.OpenRead(sourcePath);
        var iv = new byte[16];
        if (input.Read(iv, 0, iv.Length) != iv.Length)
            throw new InvalidDataException("Arquivo de quarentena inválido.");

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = GetLocalKey();
        aes.IV = iv;

        using var output = File.Create(destinationPath);
        using var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
        crypto.CopyTo(output);
    }
}
