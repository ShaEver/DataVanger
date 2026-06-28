using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DataVanger.Core;

/// <summary>
/// Identity-assurance tiers for trusted-publisher decisions.
/// The application default is <see cref="ChainAndName"/>; Substring remains
/// available only as an explicit compatibility mode.
/// </summary>
public enum PublisherValidationMode
{
    /// <summary>Tier 1 (legacy): case-insensitive trusted-name substring match. No certificate required.</summary>
    Substring = 0,

    /// <summary>Tier 2 (opt-in): verified certificate chain AND a trusted-name match. Requires a certificate.</summary>
    ChainAndName = 1,

    /// <summary>Tier 3 (opt-in): verified certificate chain AND a configured thumbprint match. Requires a certificate.</summary>
    ChainAndThumbprint = 2,
}

/// <summary>
/// BETA 11D — graduated publisher trust state derived from signature verification +
/// signer identity. Ordered from least to most trusted. Trust is RELIEF, never
/// immunity: confirmed malware (known-bad hash / confirmed YARA) always overrides,
/// and a trusted publisher can still surface with actionable evidence.
/// </summary>
public enum PublisherTrustLevel
{
    /// <summary>No signature at all.</summary>
    Unsigned = 0,
    /// <summary>A signature is present but did not verify — treated like unsigned (no relief).</summary>
    Invalid = 1,
    /// <summary>Validly signed, but the signer is not on the trusted list (measured relief).</summary>
    Valid = 2,
    /// <summary>Validly signed by a trusted publisher (strong relief).</summary>
    Trusted = 3,
    /// <summary>Validly catalog-signed Windows/Microsoft OS component (strong relief).</summary>
    TrustedWindowsComponent = 4,
}

/// <summary>
/// Opt-in, fail-safe publisher identity evaluator.
///
/// Honesty / safety contract (enforced by this code, not just documented):
///   - Default mode <see cref="PublisherValidationMode.ChainAndName"/> requires
///     offline-valid certificate-chain evidence plus an anchored name match.
///   - Stronger modes require certificate evidence. When the caller only has a signer-name
///     string (the CURRENT production path via <c>WinTrust.GetSignerSubject</c>), stronger modes
///     <b>fail closed</b> (<see cref="IsTrustedByName"/> returns false) — missing/failed
///     verification never upgrades trust.
///   - Certificate-chain validation (<see cref="ValidateChain"/>) performs NO network revocation
///     (offline, deterministic) and is fail-closed on any error.
///   - This evaluator only ever decides "is this signer trusted enough for relief in the
///     already-safe path"; it can NEVER override known-bad / confirmed-malicious classification.
///     That precedence lives in the callers (ScanEngine gate / ReputationEngine) and is unchanged.
/// </summary>
public static class PublisherIdentity
{
    // ─── Pure, platform-independent helpers (fully testable without certificates) ───

    /// <summary>
    /// Legacy trusted-name match: case-insensitive substring containment of the signer
    /// <paramref name="subject"/> against the trusted entries. Byte-for-byte equivalent to the
    /// previous ScanEngine/ReputationEngine logic.
    /// </summary>
    public static bool MatchesTrustedName(string? subject, IEnumerable<string>? trusted)
    {
        if (string.IsNullOrWhiteSpace(subject) || trusted is null) return false;
        foreach (var p in trusted)
            if (!string.IsNullOrWhiteSpace(p) && subject.Contains(p, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    // ─── BETA 11D — anchored, spoof-resistant trusted-name matching ───
    // A trusted entry matches only the START of an RDN component value at a real
    // boundary (whitespace or comma), so it can NEVER be granted by the name merely
    // appearing somewhere in the subject. Examples:
    //   "CN=Microsoft Corporation, O=..."   + "Microsoft"  → trusted
    //   "CN=Evil Microsoft Corp"            + "Microsoft"  → NOT trusted
    //   "CN=Microsofty Ltd"                 + "Microsoft"  → NOT trusted
    //   "CN=Anthropic-Evil"                 + "Anthropic"  → NOT trusted
    // Used together with a REQUIRED valid signature (callers only consult trust on a
    // verified signer), so a forged subject string alone never reaches this match.

    /// <summary>
    /// Anchored trusted-name match over the RDN component values of <paramref name="subject"/>.
    /// Spoof-resistant replacement for raw substring containment. Never throws.
    /// </summary>
    public static bool MatchesTrustedNameAnchored(string? subject, IEnumerable<string>? trusted)
    {
        if (string.IsNullOrWhiteSpace(subject) || trusted is null) return false;
        var values = ExtractRdnValues(subject);
        if (values.Count == 0) return false;
        foreach (var raw in trusted)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var name = raw.Trim();
            foreach (var v in values)
                if (AnchoredValueMatch(v, name)) return true;
        }
        return false;
    }

    private static List<string> ExtractRdnValues(string subject)
    {
        // Pragmatic RDN split: separate on commas, take the value after the first '=',
        // and strip surrounding quotes/whitespace. Good enough for Authenticode subjects
        // and strictly stronger than the previous match-anywhere behaviour.
        var values = new List<string>();
        foreach (var part in subject.Split(','))
        {
            var p = part.Trim();
            int eq = p.IndexOf('=');
            string val = (eq >= 0 ? p.Substring(eq + 1) : p).Trim().Trim('"').Trim();
            if (val.Length > 0) values.Add(val);
        }
        return values;
    }

    private static bool AnchoredValueMatch(string value, string trusted)
    {
        if (value.Equals(trusted, StringComparison.OrdinalIgnoreCase)) return true;
        if (value.Length > trusted.Length && value.StartsWith(trusted, StringComparison.OrdinalIgnoreCase))
        {
            char next = value[trusted.Length];
            return char.IsWhiteSpace(next) || next == ','; // real RDN/word boundary only
        }
        return false;
    }

    /// <summary>
    /// Production trusted-publisher decision by signer name (BETA 11D). Uses ANCHORED
    /// matching over the configured trusted names. Stronger validation modes still fail
    /// closed on the name-only path (no certificate to verify). Never throws.
    /// </summary>
    public static bool IsTrustedPublisherName(string? subject, AppSettings? settings)
    {
        if (settings is null) return false;
        if (settings.PublisherValidationMode == PublisherValidationMode.Substring)
            return MatchesTrustedNameAnchored(subject, TrustedNames(settings));
        // ChainAndName / ChainAndThumbprint need certificate evidence the name-only path
        // cannot supply — fail closed.
        return false;
    }

    /// <summary>
    /// BETA 11D — map a signature verification result to a graduated trust level. Trust
    /// requires a VALID signature; an unverified-but-present signature is <see cref="PublisherTrustLevel.Invalid"/>
    /// (no relief). A catalog-signed Microsoft signer maps to
    /// <see cref="PublisherTrustLevel.TrustedWindowsComponent"/>. Never throws.
    /// </summary>
    internal static PublisherTrustLevel EvaluatePublisherTrust(SignatureVerificationResult? result, AppSettings? settings)
    {
        if (result is null || !result.IsSigned)
            return (result?.SignaturePresentButUnverified ?? false)
                ? PublisherTrustLevel.Invalid
                : PublisherTrustLevel.Unsigned;

        bool trusted;
        if (settings?.PublisherValidationMode == PublisherValidationMode.Substring)
        {
            trusted = IsTrustedPublisherName(result.SignerSubject, settings);
        }
        else
        {
            trusted = false;
            try
            {
                if (result.SignerCertificateRawData.Length > 0)
                {
                    using var certificate = new X509Certificate2(result.SignerCertificateRawData);
                    trusted = IsTrustedByCertificate(certificate, settings);
                }
            }
            catch (CryptographicException) { trusted = false; }
            catch (ArgumentException) { trusted = false; }
        }

        if (!trusted)
            return PublisherTrustLevel.Valid;

        bool microsoft = MatchesTrustedNameAnchored(result.SignerSubject, new[] { "Microsoft" });
        return (microsoft && result.Source == SignatureSource.Catalog)
            ? PublisherTrustLevel.TrustedWindowsComponent
            : PublisherTrustLevel.Trusted;
    }

    /// <summary>
    /// Normalize a thumbprint for comparison: drop spaces/colons/dashes, strip a leading "0x",
    /// upper-case. Returns "" for null/empty or anything that is not pure hex (so malformed
    /// configuration can never match).
    /// </summary>
    public static string NormalizeThumbprint(string? thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return "";
        var sb = new StringBuilder(thumbprint.Length);
        foreach (var ch in thumbprint)
        {
            if (ch is ' ' or ':' or '-' or '\t') continue;
            sb.Append(ch);
        }
        var s = sb.ToString();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
        s = s.ToUpperInvariant();
        if (s.Length == 0) return "";
        foreach (var ch in s)
            if (!Uri.IsHexDigit(ch)) return ""; // malformed → never matches
        return s;
    }

    /// <summary>
    /// True iff <paramref name="candidate"/> normalizes to one of the <paramref name="configured"/>
    /// thumbprints (both non-empty after normalization). Empty/malformed config never matches.
    /// </summary>
    public static bool MatchesConfiguredThumbprint(string? candidate, IEnumerable<string>? configured)
    {
        var norm = NormalizeThumbprint(candidate);
        if (norm.Length == 0 || configured is null) return false;
        foreach (var t in configured)
        {
            var c = NormalizeThumbprint(t);
            if (c.Length > 0 && string.Equals(c, norm, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    // ─── Name-only evaluation: the CURRENT production call path ───
    // ScanEngine/ReputationEngine only have the signer-name string (WinTrust discards the cert).

    /// <summary>
    /// Evaluate trust from a signer-name string only. <see cref="PublisherValidationMode.Substring"/>
    /// uses the legacy name match; stronger modes have no certificate to verify and therefore
    /// FAIL CLOSED (return false). Never throws.
    /// </summary>
    public static bool IsTrustedByName(string? subject, AppSettings? settings)
    {
        if (settings is null) return false;
        if (settings.PublisherValidationMode == PublisherValidationMode.Substring)
            return MatchesTrustedName(subject, TrustedNames(settings));

        // ChainAndName / ChainAndThumbprint require certificate evidence that the name-only
        // path cannot provide. Fail closed — never upgrade trust on missing verification.
        return false;
    }

    // ─── Certificate-based evaluation: testable now; ready for future WinTrust wiring ───

    /// <summary>
    /// Evaluate trust when a certificate is available. Substring → name match; ChainAndName →
    /// chain valid AND name match; ChainAndThumbprint → chain valid AND configured thumbprint
    /// match. Any failure (incl. unverified chain, missing/mismatched/malformed thumbprint, or
    /// exception) yields false. Never throws.
    /// </summary>
    public static bool IsTrustedByCertificate(X509Certificate2? cert, AppSettings? settings)
    {
        if (cert is null || settings is null) return false;
        switch (settings.PublisherValidationMode)
        {
            case PublisherValidationMode.Substring:
                return MatchesTrustedNameAnchored(cert.Subject, TrustedNames(settings));

            case PublisherValidationMode.ChainAndName:
                return ValidateChain(cert) && MatchesTrustedNameAnchored(cert.Subject, TrustedNames(settings));

            case PublisherValidationMode.ChainAndThumbprint:
                return ValidateChain(cert)
                    && MatchesConfiguredThumbprint(cert.Thumbprint, settings.TrustedPublisherThumbprints);

            default:
                return false;
        }
    }

    /// <summary>
    /// Build and validate an X509 chain with NO network revocation (offline, deterministic).
    /// Returns false on non-Windows hosts and on any failure/exception (fail closed). Never throws.
    /// A self-signed / untrusted-root certificate returns false here, which is the intended
    /// fail-closed behaviour for stronger modes.
    /// </summary>
    public static bool ValidateChain(X509Certificate2? cert)
    {
        if (cert is null) return false;
        if (!OperatingSystem.IsWindows()) return false; // Authenticode chain trust is Windows-specific here
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;      // never go online by default
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag; // strict
            return chain.Build(cert);
        }
        catch (CryptographicException) { return false; }
        catch (ArgumentException) { return false; }
    }

    private static IEnumerable<string> TrustedNames(AppSettings settings) =>
        (settings.TrustedPublishers ?? new List<string>())
            .Concat(settings.ExtraTrustedPublishers ?? new List<string>());
}
