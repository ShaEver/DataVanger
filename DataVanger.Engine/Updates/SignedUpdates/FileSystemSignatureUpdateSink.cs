using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Crash-consistent signed-feed sink. Every accepted release is an immutable version;
/// activation changes only a small atomic pointer. User/baseline signature files are
/// outside this tree and are never deleted or rewritten.
/// </summary>
public sealed class FileSystemSignatureUpdateSink : IUpdateContentSink
{
    public const string TransactionRootName = ".signed-feed";
    public const string MaliciousFeedFileName = "known_malicious_sha256.feed.txt";
    public const string SafeFeedFileName = "known_safe_sha256.feed.txt";
    public const string YaraFeedPrefix = "feed__";
    private const string YaraDirName = "yara_rules";
    private const int MaxRetainedVersions = 6;
    private const long MaxVersionBytes = 256L * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly string _transactionRoot;
    private readonly object _gate = new();
    private readonly Action<UpdateFaultPoint>? _fault;

    public FileSystemSignatureUpdateSink(string signatureRoot, Action<UpdateFaultPoint>? faultInjector = null)
    {
        if (string.IsNullOrWhiteSpace(signatureRoot)) throw new ArgumentException("Signature root is required.", nameof(signatureRoot));
        _transactionRoot = Path.Combine(Path.GetFullPath(signatureRoot), TransactionRootName);
        _fault = faultInjector;
        Directory.CreateDirectory(_transactionRoot);
        RecoverAll();
    }

    // Compatibility overload for callers that stage the sink directly. Production passes
    // the verifier's canonical manifest hash through IUpdateContentSink.
    public void Stage(string feedId, long sequence, IReadOnlyList<StagedPackage> packages)
        => Stage(feedId, sequence, ComputePackageSetHash(packages), packages);

    public void Stage(string feedId, long sequence, string canonicalManifestSha256, IReadOnlyList<StagedPackage> packages)
    {
        if (packages is null) throw new ArgumentNullException(nameof(packages));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        canonicalManifestSha256 = NormalizeHash(canonicalManifestSha256);

        lock (_gate)
        {
            string feedRoot = FeedRoot(feedId);
            Directory.CreateDirectory(VersionsRoot(feedRoot));
            RecoverFeed(feedRoot);

            var active = ReadPointer(ActivePath(feedRoot));
            if (active is not null && sequence < active.Sequence)
                throw new InvalidOperationException("Content sink rejected a lower sequence.");
            if (active is not null && sequence == active.Sequence &&
                !string.Equals(active.CanonicalManifestSha256, canonicalManifestSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Content sink detected a same-sequence canonical-hash conflict.");

            string versionName = VersionName(sequence, canonicalManifestSha256);
            string finalDir = Path.Combine(VersionsRoot(feedRoot), versionName);
            if (Directory.Exists(finalDir))
            {
                VerifyVersion(finalDir, sequence, canonicalManifestSha256);
                WriteJournal(feedRoot, new UpdateJournal { State = UpdateJournalState.Verified, TargetVersion = versionName, Sequence = sequence, CanonicalManifestSha256 = canonicalManifestSha256 });
                return;
            }

            string stagingDir = Path.Combine(VersionsRoot(feedRoot), ".staging-" + Guid.NewGuid().ToString("N"));
            WriteJournal(feedRoot, new UpdateJournal { State = UpdateJournalState.Staging, TargetVersion = versionName, StagingDirectory = Path.GetFileName(stagingDir), Sequence = sequence, CanonicalManifestSha256 = canonicalManifestSha256 });
            Directory.CreateDirectory(stagingDir);
            try
            {
                _fault?.Invoke(UpdateFaultPoint.BeforeStageWrite);
                var files = ProjectVersion(stagingDir, packages);
                _fault?.Invoke(UpdateFaultPoint.AfterStageWrite);
                long total = files.Sum(f => f.Length);
                if (total > MaxVersionBytes) throw new InvalidDataException("Staged update exceeds the version size limit.");

                var manifest = new VersionManifest
                {
                    SchemaVersion = 1,
                    Sequence = sequence,
                    CanonicalManifestSha256 = canonicalManifestSha256,
                    Files = files,
                };
                WriteJsonDurable(Path.Combine(stagingDir, "version.json"), manifest);
                _fault?.Invoke(UpdateFaultPoint.BeforeVerify);
                VerifyVersion(stagingDir, sequence, canonicalManifestSha256);
                _fault?.Invoke(UpdateFaultPoint.BeforeVersionRename);
                Directory.Move(stagingDir, finalDir);
                VerifyVersion(finalDir, sequence, canonicalManifestSha256);
                WriteJournal(feedRoot, new UpdateJournal { State = UpdateJournalState.Verified, TargetVersion = versionName, Sequence = sequence, CanonicalManifestSha256 = canonicalManifestSha256 });
            }
            catch (Exception ex)
            {
                TryDeleteDirectory(stagingDir);
                WriteJournal(feedRoot, new UpdateJournal { State = UpdateJournalState.RolledBack, TargetVersion = versionName, Sequence = sequence, CanonicalManifestSha256 = canonicalManifestSha256, LastFailure = ex.GetType().Name + ": " + ex.Message });
                throw;
            }
        }
    }

    public void Commit(string feedId, long sequence)
    {
        lock (_gate)
        {
            string feedRoot = FeedRoot(feedId);
            RecoverFeed(feedRoot);
            var journal = ReadJournal(feedRoot);
            if (journal is null || journal.State != UpdateJournalState.Verified || journal.Sequence != sequence)
                throw new InvalidOperationException("No matching verified version to commit.");

            string targetDir = Path.Combine(VersionsRoot(feedRoot), journal.TargetVersion);
            VerifyVersion(targetDir, journal.Sequence, journal.CanonicalManifestSha256);
            var prior = ReadPointer(ActivePath(feedRoot));
            if (prior is not null)
            {
                VerifyVersion(Path.Combine(VersionsRoot(feedRoot), prior.Version), prior.Sequence, prior.CanonicalManifestSha256);
                WritePointer(LkgPath(feedRoot), prior);
            }

            var next = new VersionPointer(journal.TargetVersion, journal.Sequence, journal.CanonicalManifestSha256);
            try
            {
                _fault?.Invoke(UpdateFaultPoint.BeforePointerCommit);
                journal.State = UpdateJournalState.Activating;
                WriteJournal(feedRoot, journal);
                WritePointer(ActivePath(feedRoot), next);
                _fault?.Invoke(UpdateFaultPoint.AfterPointerCommit);
                VerifyPointer(feedRoot, next);
                journal.State = UpdateJournalState.Active;
                WriteJournal(feedRoot, journal);
                _fault?.Invoke(UpdateFaultPoint.BeforeCleanup);
                GarbageCollect(feedRoot);
            }
            catch (Exception ex)
            {
                journal.LastFailure = ex.GetType().Name + ": " + ex.Message;
                WriteJournal(feedRoot, journal);
                throw;
            }
        }
    }

    public void Restore(string feedId)
    {
        lock (_gate)
        {
            string feedRoot = FeedRoot(feedId);
            RecoverFeed(feedRoot);
            var lkg = ReadPointer(LkgPath(feedRoot)) ?? throw new InvalidOperationException("No last-known-good content to restore.");
            VerifyPointer(feedRoot, lkg);
            var journal = new UpdateJournal { State = UpdateJournalState.RollbackPending, TargetVersion = lkg.Version, Sequence = lkg.Sequence, CanonicalManifestSha256 = lkg.CanonicalManifestSha256 };
            WriteJournal(feedRoot, journal);
            WritePointer(ActivePath(feedRoot), lkg);
            VerifyPointer(feedRoot, lkg);
            File.Delete(LkgPath(feedRoot));
            if (File.Exists(LkgPath(feedRoot))) throw new IOException("LKG pointer could not be consumed.");
            journal.State = UpdateJournalState.RolledBack;
            WriteJournal(feedRoot, journal);
            GarbageCollect(feedRoot);
        }
    }

    public UpdateContentHealth GetHealth(string feedId)
    {
        lock (_gate)
        {
            string root = FeedRoot(feedId);
            var journal = ReadJournal(root);
            return new UpdateContentHealth(
                ReadPointer(ActivePath(root))?.Version,
                ReadPointer(LkgPath(root))?.Version,
                journal is { State: UpdateJournalState.Staging or UpdateJournalState.Verified or UpdateJournalState.Activating or UpdateJournalState.RollbackPending } ? journal.TargetVersion : null,
                journal?.State.ToString() ?? "None",
                journal?.LastFailure ?? string.Empty);
        }
    }

    private List<FileDigest> ProjectVersion(string root, IReadOnlyList<StagedPackage> packages)
    {
        var paths = new List<string>();
        var malicious = new SortedSet<string>(StringComparer.Ordinal);
        var safe = new SortedSet<string>(StringComparer.Ordinal);
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int yaraIndex = 0;

        string packagesDir = Path.Combine(root, "packages");
        Directory.CreateDirectory(packagesDir);
        foreach (var pkg in packages)
        {
            string rawName = Sanitize(pkg.Entry.Id) + "-" + UpdatePackageVerifier.ComputeSha256Hex(pkg.Content)[..16] + ".pkg";
            string rawPath = Path.Combine(packagesDir, rawName);
            WriteFileDurable(rawPath, pkg.Content);
            paths.Add(rawPath);

            switch (pkg.Entry.Kind)
            {
                case UpdatePackageKind.HashBlacklist:
                    foreach (var h in ParseHashes(pkg.Content)) malicious.Add(h);
                    break;
                case UpdatePackageKind.HashAllowlist:
                    foreach (var h in ParseHashes(pkg.Content)) safe.Add(h);
                    break;
                case UpdatePackageKind.YaraRules:
                    string yaraDir = Path.Combine(root, YaraDirName);
                    Directory.CreateDirectory(yaraDir);
                    string baseName = YaraFeedPrefix + Sanitize(string.IsNullOrEmpty(pkg.Entry.Id) ? "rule" + yaraIndex : pkg.Entry.Id);
                    string name = baseName + ".yar";
                    for (int dup = 1; !usedNames.Add(name); dup++) name = baseName + "_" + dup + ".yar";
                    string yaraPath = Path.Combine(yaraDir, name);
                    WriteFileDurable(yaraPath, pkg.Content);
                    paths.Add(yaraPath);
                    yaraIndex++;
                    break;
            }
        }

        if (malicious.Count > 0)
        {
            string path = Path.Combine(root, MaliciousFeedFileName);
            WriteFileDurable(path, HashFileBytes(malicious, "malicious"));
            paths.Add(path);
        }
        if (safe.Count > 0)
        {
            string path = Path.Combine(root, SafeFeedFileName);
            WriteFileDurable(path, HashFileBytes(safe, "safe"));
            paths.Add(path);
        }

        return paths.Select(p => new FileDigest(Path.GetRelativePath(root, p).Replace('\\', '/'), new FileInfo(p).Length, ComputeFileHash(p))).ToList();
    }

    private static void VerifyVersion(string versionDir, long sequence, string canonicalHash)
    {
        string metadataPath = Path.Combine(versionDir, "version.json");
        var manifest = ReadJson<VersionManifest>(metadataPath) ?? throw new InvalidDataException("Version manifest is missing or corrupt.");
        if (manifest.SchemaVersion != 1 || manifest.Sequence != sequence ||
            !string.Equals(manifest.CanonicalManifestSha256, canonicalHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Version identity mismatch.");
        if (manifest.Files.Count > 10_000 || manifest.Files.Sum(f => f.Length) > MaxVersionBytes)
            throw new InvalidDataException("Version limits exceeded.");
        foreach (var file in manifest.Files)
        {
            if (file.RelativePath.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(file.RelativePath)) throw new InvalidDataException("Unsafe version path.");
            string path = Path.GetFullPath(Path.Combine(versionDir, file.RelativePath));
            if (!path.StartsWith(Path.GetFullPath(versionDir) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Version path escaped root.");
            var info = new FileInfo(path);
            if (!info.Exists || info.Length != file.Length || !string.Equals(ComputeFileHash(path), file.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Version file verification failed: " + file.RelativePath);
        }
    }

    private void RecoverAll()
    {
        foreach (var feedRoot in Directory.EnumerateDirectories(_transactionRoot))
        {
            try { RecoverFeed(feedRoot); } catch { /* health journal remains authoritative */ }
        }
    }

    private static void RecoverFeed(string feedRoot)
    {
        var j = ReadJournal(feedRoot);
        if (j is null) return;
        if (j.State == UpdateJournalState.Staging)
        {
            if (!string.IsNullOrWhiteSpace(j.StagingDirectory)) TryDeleteDirectory(Path.Combine(VersionsRoot(feedRoot), j.StagingDirectory));
            j.State = UpdateJournalState.RolledBack;
            j.LastFailure = "Interrupted staging discarded during recovery.";
            WriteJournal(feedRoot, j);
            return;
        }
        if (j.State == UpdateJournalState.Verified)
        {
            // Verified but never activated: previous active pointer remains authoritative.
            return;
        }
        if (j.State == UpdateJournalState.Activating)
        {
            var active = ReadPointer(ActivePath(feedRoot));
            if (active is not null && active.Version == j.TargetVersion)
            {
                VerifyPointer(feedRoot, active);
                j.State = UpdateJournalState.Active;
            }
            else
            {
                j.State = UpdateJournalState.RolledBack;
                j.LastFailure = "Interrupted activation left previous active version in place.";
            }
            WriteJournal(feedRoot, j);
            return;
        }
        if (j.State == UpdateJournalState.RollbackPending)
        {
            var target = new VersionPointer(j.TargetVersion, j.Sequence, j.CanonicalManifestSha256);
            VerifyPointer(feedRoot, target);
            WritePointer(ActivePath(feedRoot), target);
            if (File.Exists(LkgPath(feedRoot))) File.Delete(LkgPath(feedRoot));
            j.State = UpdateJournalState.RolledBack;
            WriteJournal(feedRoot, j);
        }
    }

    private static void VerifyPointer(string feedRoot, VersionPointer pointer)
        => VerifyVersion(Path.Combine(VersionsRoot(feedRoot), pointer.Version), pointer.Sequence, pointer.CanonicalManifestSha256);

    private static void GarbageCollect(string feedRoot)
    {
        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var active = ReadPointer(ActivePath(feedRoot)); if (active is not null) keep.Add(active.Version);
        var lkg = ReadPointer(LkgPath(feedRoot)); if (lkg is not null) keep.Add(lkg.Version);
        var dirs = Directory.EnumerateDirectories(VersionsRoot(feedRoot))
            .Where(d => !Path.GetFileName(d).StartsWith(".staging-", StringComparison.Ordinal))
            .OrderByDescending(Directory.GetCreationTimeUtc).ToList();
        foreach (var dir in dirs.Take(MaxRetainedVersions)) keep.Add(Path.GetFileName(dir));
        foreach (var dir in dirs.Where(d => !keep.Contains(Path.GetFileName(d)))) TryDeleteDirectory(dir);
    }

    private string FeedRoot(string feedId) => Path.Combine(_transactionRoot, SanitizeFeedId(feedId));
    private static string VersionsRoot(string feedRoot) => Path.Combine(feedRoot, "versions");
    private static string ActivePath(string feedRoot) => Path.Combine(feedRoot, "active.json");
    private static string LkgPath(string feedRoot) => Path.Combine(feedRoot, "lkg.json");
    private static string JournalPath(string feedRoot) => Path.Combine(feedRoot, "journal.json");
    private static string VersionName(long sequence, string hash) => sequence.ToString("D20") + "-" + hash.ToLowerInvariant();

    private static void WritePointer(string path, VersionPointer pointer) => WriteJsonDurable(path, pointer);
    private static VersionPointer? ReadPointer(string path) => ReadJson<VersionPointer>(path);
    private static UpdateJournal? ReadJournal(string root) => ReadJson<UpdateJournal>(JournalPath(root));
    private static void WriteJournal(string root, UpdateJournal journal) { Directory.CreateDirectory(root); WriteJsonDurable(JournalPath(root), journal); }

    private static T? ReadJson<T>(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path, Encoding.UTF8), JsonOptions) : default; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return default; }
    }

    private static void WriteJsonDurable<T>(string path, T value) => WriteFileDurable(path, JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions));

    private static void WriteFileDurable(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81_920, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            using (var verify = new FileStream(temp, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (verify.Length != bytes.LongLength) throw new IOException("Durable write length verification failed.");
            }
            File.Move(temp, path, overwrite: true);
        }
        finally { try { if (File.Exists(temp)) File.Delete(temp); } catch (IOException) { /* best effort */ } catch (UnauthorizedAccessException) { /* best effort */ } }
    }

    private static string ComputeFileHash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string ComputePackageSetHash(IReadOnlyList<StagedPackage> packages)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var p in packages.OrderBy(p => p.Entry.Id, StringComparer.Ordinal))
        {
            hash.AppendData(Encoding.UTF8.GetBytes(p.Entry.Id ?? string.Empty));
            hash.AppendData(p.Content);
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static string NormalizeHash(string value)
    {
        value = value?.Trim().ToLowerInvariant() ?? string.Empty;
        if (value.Length != 64 || !value.All(Uri.IsHexDigit)) throw new ArgumentException("Canonical manifest SHA-256 is invalid.");
        return value;
    }

    private static IEnumerable<string> ParseHashes(byte[] content)
    {
        foreach (var line in Encoding.UTF8.GetString(content).Split('\n'))
        {
            var clean = line.Split('#', 2)[0].Split(';', 2)[0].Trim();
            var token = clean.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.ToUpperInvariant() ?? string.Empty;
            if (token.Length == 64 && token.All(Uri.IsHexDigit)) yield return token;
        }
    }

    private static byte[] HashFileBytes(IEnumerable<string> hashes, string label)
        => Encoding.UTF8.GetBytes("# DataVanger signed-feed " + label + " hashes (immutable version).\n" + string.Join("\n", hashes) + "\n");

    private static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder();
        foreach (char c in value ?? string.Empty) sb.Append(c is '/' or '\\' || invalid.Contains(c) ? '_' : c);
        return sb.Length == 0 ? "item" : sb.ToString();
    }

    private static string SanitizeFeedId(string feedId) => Sanitize(feedId).ToLowerInvariant();
    private static void TryDeleteDirectory(string path) { try { if (Directory.Exists(path)) Directory.Delete(path, true); } catch (IOException) { /* best effort */ } catch (UnauthorizedAccessException) { /* best effort */ } }

    public enum UpdateJournalState { Staging, Verified, Activating, Active, RollbackPending, RolledBack }
    public enum UpdateFaultPoint { BeforeStageWrite, AfterStageWrite, BeforeVerify, BeforeVersionRename, BeforePointerCommit, AfterPointerCommit, BeforeCleanup }
    public sealed record UpdateContentHealth(string? ActiveVersion, string? LastKnownGoodVersion, string? PendingVersion, string TransactionState, string LastFailure);
    private sealed record VersionPointer(string Version, long Sequence, string CanonicalManifestSha256);
    private sealed record FileDigest(string RelativePath, long Length, string Sha256);
    private sealed class VersionManifest
    {
        public int SchemaVersion { get; set; }
        public long Sequence { get; set; }
        public string CanonicalManifestSha256 { get; set; } = string.Empty;
        public List<FileDigest> Files { get; set; } = new();
    }
    private sealed class UpdateJournal
    {
        public UpdateJournalState State { get; set; }
        public string TargetVersion { get; set; } = string.Empty;
        public string StagingDirectory { get; set; } = string.Empty;
        public long Sequence { get; set; }
        public string CanonicalManifestSha256 { get; set; } = string.Empty;
        public string LastFailure { get; set; } = string.Empty;
    }
}
