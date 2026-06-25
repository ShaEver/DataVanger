using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using DataVanger.Shared.Updates;

namespace DataVanger.Engine.Updates.SignedUpdates;

/// <summary>
/// Filesystem <see cref="IUpdateContentSink"/> that projects cryptographically verified update
/// packages into the live signature root, so a signed feed actually updates detection.
///
/// All trust decisions (manifest signature, anti-downgrade sequencing, package hash/size) are
/// made upstream in <see cref="SignedUpdateService"/> and the verifiers — this sink only persists
/// content that has already been verified. It is the missing apply bridge between the signed
/// pipeline and the on-disk signature pack consumed by the scanner.
///
/// Projection (only ever touches dedicated feed files — never the user or baseline lists):
/// <list type="bullet">
///   <item><see cref="UpdatePackageKind.HashBlacklist"/> → <c>known_malicious_sha256.feed.txt</c></item>
///   <item><see cref="UpdatePackageKind.HashAllowlist"/> → <c>known_safe_sha256.feed.txt</c></item>
///   <item><see cref="UpdatePackageKind.YaraRules"/> → <c>yara_rules/feed__&lt;id&gt;.yar</c></item>
/// </list>
/// The hash feed files are unioned by the scanner's signature loader by filename agreement
/// (the loader lives in the UI app layer, which this engine does not reference); YARA feed
/// rules are picked up by the lightweight rule loader that already scans <c>yara_rules/</c>.
///
/// Active and last-known-good package sets are held per feed for rollback; the projected files
/// are a pure function of the active set and are rewritten on every Commit/Restore.
/// </summary>
public sealed class FileSystemSignatureUpdateSink : IUpdateContentSink
{
    /// <summary>Feed-applied malicious hashes. MUST match the name unioned by the scanner's loader.</summary>
    public const string MaliciousFeedFileName = "known_malicious_sha256.feed.txt";

    /// <summary>Feed-applied known-safe hashes. MUST match the name unioned by the scanner's loader.</summary>
    public const string SafeFeedFileName = "known_safe_sha256.feed.txt";

    /// <summary>Prefix marking YARA rule files owned by the feed (so they can be cleared/replaced safely).</summary>
    public const string YaraFeedPrefix = "feed__";

    private const string YaraDirName = "yara_rules";

    private sealed class FeedState
    {
        public long ActiveSequence;
        public List<StagedPackage> Active = new();
        public bool HasLastKnownGood;
        public long LastKnownGoodSequence;
        public List<StagedPackage> LastKnownGood = new();
        public List<StagedPackage>? Pending;
        public long PendingSequence;
    }

    private readonly string _signatureRoot;
    private readonly object _gate = new();
    private readonly Dictionary<string, FeedState> _feeds = new(StringComparer.Ordinal);

    public FileSystemSignatureUpdateSink(string signatureRoot)
    {
        if (string.IsNullOrWhiteSpace(signatureRoot))
            throw new ArgumentException("Signature root is required.", nameof(signatureRoot));
        _signatureRoot = signatureRoot;
    }

    public void Stage(string feedId, long sequence, IReadOnlyList<StagedPackage> packages)
    {
        if (packages is null) throw new ArgumentNullException(nameof(packages));
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            feed.Pending = new List<StagedPackage>(packages);
            feed.PendingSequence = sequence;
        }
    }

    public void Commit(string feedId, long sequence)
    {
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            if (feed.Pending is null || feed.PendingSequence != sequence)
                throw new InvalidOperationException("No matching staged content to commit.");

            if (feed.ActiveSequence > 0)
            {
                feed.LastKnownGood = feed.Active;
                feed.LastKnownGoodSequence = feed.ActiveSequence;
                feed.HasLastKnownGood = true;
            }

            feed.Active = feed.Pending;
            feed.ActiveSequence = sequence;
            feed.Pending = null;
            feed.PendingSequence = 0;

            Project(feed.Active);
        }
    }

    public void Restore(string feedId)
    {
        lock (_gate)
        {
            var feed = GetOrCreate(feedId);
            if (!feed.HasLastKnownGood)
                throw new InvalidOperationException("No last-known-good content to restore.");

            feed.Active = feed.LastKnownGood;
            feed.ActiveSequence = feed.LastKnownGoodSequence;
            feed.HasLastKnownGood = false;
            feed.LastKnownGood = new List<StagedPackage>();
            feed.LastKnownGoodSequence = 0;
            feed.Pending = null;
            feed.PendingSequence = 0;

            Project(feed.Active);
        }
    }

    /// <summary>
    /// Rewrites the projected signature files from the active package set. Clears the previously
    /// projected feed files first so a package removed from the feed leaves no stale artifact.
    /// </summary>
    private void Project(IReadOnlyList<StagedPackage> active)
    {
        Directory.CreateDirectory(_signatureRoot);
        string yaraDir = Path.Combine(_signatureRoot, YaraDirName);
        Directory.CreateDirectory(yaraDir);

        // 1. Clear prior feed projection (never touches user/baseline files).
        DeleteIfExists(Path.Combine(_signatureRoot, MaliciousFeedFileName));
        DeleteIfExists(Path.Combine(_signatureRoot, SafeFeedFileName));
        foreach (var stale in SafeEnumerate(yaraDir, YaraFeedPrefix + "*.yar"))
            DeleteIfExists(stale);

        // 2. Collect hash sets and write YARA rules.
        var malicious = new SortedSet<string>(StringComparer.Ordinal);
        var safe = new SortedSet<string>(StringComparer.Ordinal);
        int yaraIndex = 0;
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pkg in active)
        {
            switch (pkg.Entry.Kind)
            {
                case UpdatePackageKind.HashBlacklist:
                    foreach (var h in ParseHashes(pkg.Content)) malicious.Add(h);
                    break;
                case UpdatePackageKind.HashAllowlist:
                    foreach (var h in ParseHashes(pkg.Content)) safe.Add(h);
                    break;
                case UpdatePackageKind.YaraRules:
                    string baseName = YaraFeedPrefix + Sanitize(string.IsNullOrEmpty(pkg.Entry.Id) ? ("rule" + yaraIndex) : pkg.Entry.Id);
                    string name = baseName + ".yar";
                    int dup = 1;
                    while (!usedNames.Add(name)) name = baseName + "_" + dup++ + ".yar";
                    AtomicWrite(Path.Combine(yaraDir, name), pkg.Content);
                    yaraIndex++;
                    break;
                default:
                    break; // other kinds are not projected by this sink yet
            }
        }

        if (malicious.Count > 0)
            AtomicWrite(Path.Combine(_signatureRoot, MaliciousFeedFileName), HashFileBytes(malicious, "malicious"));
        if (safe.Count > 0)
            AtomicWrite(Path.Combine(_signatureRoot, SafeFeedFileName), HashFileBytes(safe, "safe"));
    }

    private static IEnumerable<string> ParseHashes(byte[] content)
    {
        string text = Encoding.UTF8.GetString(content);
        foreach (var line in text.Split('\n'))
        {
            var h = ParseHashLine(line);
            if (h != null) yield return h;
        }
    }

    // Matches the scanner's SignatureDatabase.ParseHashLine semantics: strip #/; comments,
    // take the first token, normalise to upper-case, accept only 64-char hex.
    private static string? ParseHashLine(string line)
    {
        var clean = line.Split('#', 2)[0].Split(';', 2)[0].Trim();
        if (clean.Length == 0) return null;
        var token = clean.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim().ToUpperInvariant() ?? "";
        return (token.Length == 64 && token.All(Uri.IsHexDigit)) ? token : null;
    }

    private static byte[] HashFileBytes(IEnumerable<string> hashes, string label)
    {
        var sb = new StringBuilder();
        sb.Append("# DataVanger signed-feed ").Append(label).Append(" hashes (auto-generated; do not edit).\n");
        foreach (var h in hashes) sb.Append(h).Append('\n');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(c == '/' || c == '\\' || Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return sb.Length == 0 ? "rule" : sb.ToString();
    }

    private static void AtomicWrite(string path, byte[] bytes)
    {
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }

    private static void DeleteIfExists(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (UnauthorizedAccessException) { /* leave protected file; projection is best-effort */ }
        catch (IOException) { /* file busy; leave in place */ }
    }

    private static IReadOnlyList<string> SafeEnumerate(string dir, string pattern)
    {
        try { return Directory.GetFiles(dir, pattern); }
        catch (UnauthorizedAccessException) { return Array.Empty<string>(); }
        catch (IOException) { return Array.Empty<string>(); }
    }

    private FeedState GetOrCreate(string feedId)
    {
        if (!_feeds.TryGetValue(feedId, out var feed))
        {
            feed = new FeedState();
            _feeds[feedId] = feed;
        }
        return feed;
    }
}
