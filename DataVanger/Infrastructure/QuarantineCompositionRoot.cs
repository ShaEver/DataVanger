using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DataVanger.Engine.Quarantine;
using DataVanger.Infrastructure.Quarantine;
using DataVanger.Shared.Quarantine;

namespace DataVanger.Infrastructure;

/// <summary>The single application composition root for Secure Quarantine V2.</summary>
public static class QuarantineCompositionRoot
{
    public static QuarantineKeyAuthorityDescriptor KeyAuthority { get; } = new(
        "InteractiveUser/DPAPI-CurrentUser",
        OperationsMustUseIpcWhenServiceOwned: true,
        PlaintextKeyMigrationAllowed: false);
    /// <summary>
    /// Composes a persistent V2 store owned by the interactive Windows user.
    /// DPAPI uses CurrentUser; this store is not readable by a future LocalSystem
    /// service without an explicit, separately reviewed key migration.
    /// </summary>
    public static QuarantineRuntime CreateForCurrentUser(string dataRoot, string quarantineRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(quarantineRoot);

        string v2Root = Path.Combine(quarantineRoot, "v2");
        string keyRoot = Path.Combine(dataRoot, "keys");
        string auditPath = Path.Combine(dataRoot, "logs", "quarantine-v2.audit.jsonl");

        var options = QuarantineOptions.Production();
        AddForbiddenRoot(options, v2Root);
        AddForbiddenRoot(options, dataRoot);
        AddForbiddenRoot(options, AppContext.BaseDirectory);
        AddForbiddenRoot(options, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        AddForbiddenRoot(options, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddForbiddenRoot(options, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

        var store = new FileSystemQuarantineStore(v2Root);
        var service = new QuarantineService(
            store,
            new QuarantineCryptoProvider(),
            new DpapiQuarantineKeyProtector(keyRoot),
            options,
            quarantineStoreRoot: v2Root,
            auditSink: new JsonLinesQuarantineAuditSink(auditPath));

        return new QuarantineRuntime(service, service, new LegacyQuarantineInventory(quarantineRoot));
    }

    private static void AddForbiddenRoot(QuarantineOptions options, string? root)
    {
        if (!string.IsNullOrWhiteSpace(root)) options.ForbiddenRestoreRoots.Add(root);
    }
}

public sealed record QuarantineRuntime(
    IQuarantineService Service,
    IQuarantineIndex Index,
    LegacyQuarantineInventory LegacyInventory);

public sealed record QuarantineKeyAuthorityDescriptor(
    string CurrentAuthority,
    bool OperationsMustUseIpcWhenServiceOwned,
    bool PlaintextKeyMigrationAllowed);

/// <summary>
/// Append-only, structured audit sink. Events intentionally contain no original
/// path, plaintext, key material, or exception details.
/// </summary>
public sealed class JsonLinesQuarantineAuditSink : IQuarantineAuditSink
{
    private readonly string _path;
    private readonly object _gate = new();

    public JsonLinesQuarantineAuditSink(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
    }

    public void Publish(QuarantineAuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        string json = JsonSerializer.Serialize(auditEvent);
        lock (_gate)
        {
            File.AppendAllText(_path, json + Environment.NewLine);
        }
    }
}

/// <summary>
/// Read-only inventory of unauthenticated V1 artifacts. It never parses the
/// legacy JSON, decrypts payloads, trusts OriginalPath, or offers restore.
/// </summary>
public sealed class LegacyQuarantineInventory
{
    private readonly string _root;

    public LegacyQuarantineInventory(string root) => _root = Path.GetFullPath(root);

    public LegacyQuarantineSummary Inspect()
    {
        try
        {
            if (!Directory.Exists(_root)) return new LegacyQuarantineSummary(0, false);
            int payloads = Directory.EnumerateFiles(_root, "*.quarantine", SearchOption.TopDirectoryOnly).Count();
            bool indexPresent = File.Exists(Path.Combine(_root, "quarantine_index.json"));
            return new LegacyQuarantineSummary(payloads, indexPresent);
        }
        catch (Exception)
        {
            return new LegacyQuarantineSummary(0, true);
        }
    }
}

public sealed record LegacyQuarantineSummary(int PayloadCount, bool IndexPresent)
{
    public bool HasUnauthenticatedItems => PayloadCount > 0 || IndexPresent;
}
