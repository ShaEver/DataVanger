using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace DataVanger.Core;

/// <summary>
/// Source of a successful signature verification (BETA 11A). Lets callers and
/// telemetry distinguish an embedded Authenticode signature from a Windows
/// security-catalog signature without changing any trust decision.
/// </summary>
internal enum SignatureSource
{
    None = 0,
    Embedded = 1,
    Catalog = 2,
}

/// <summary>
/// Result of <see cref="WinTrust.VerifySignature"/> (BETA 11A). A small, explicit
/// model so a verification failure is never collapsed into "signed": trust is
/// granted only when <see cref="IsSigned"/> is true AND it came from a valid
/// embedded or catalog verification.
/// </summary>
internal sealed class SignatureVerificationResult
{
    public bool IsSigned { get; init; }
    public string SignerSubject { get; init; } = "";
    public SignatureSource Source { get; init; } = SignatureSource.None;

    /// <summary>
    /// DER-encoded public signer certificate used for offline chain/name or
    /// chain/thumbprint validation. Empty means certificate identity was not
    /// available and stronger publisher modes must fail closed.
    /// </summary>
    public byte[] SignerCertificateRawData { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// BETA 11D — true when an embedded signature is PRESENT but did not verify
    /// (i.e. "invalid", distinct from truly "unsigned"). Never grants relief; lets
    /// the publisher trust model map an invalid signature to its own state.
    /// </summary>
    public bool SignaturePresentButUnverified { get; init; }

    public static readonly SignatureVerificationResult Unsigned = new();
}

/// <summary>
/// P/Invoke wrapper for WinVerifyTrust — verifies Authenticode signatures.
/// </summary>
internal static class WinTrust
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint   cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint   cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint   dwUIChoice;       // WTD_UI_NONE = 2
        public uint   fdwRevocationChecks; // WTD_REVOKE_NONE = 0
        public uint   dwUnionChoice;    // WTD_CHOICE_FILE = 1
        public IntPtr pFile;
        public uint   dwStateAction;    // WTD_STATEACTION_VERIFY = 1
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint   dwProvFlags;
        public uint   dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    private const uint ERROR_SUCCESS   = 0;
    private const uint WTD_UI_NONE     = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE  = 2;

    /// <summary>Returns true if the file has a valid Authenticode signature.</summary>
    public static bool VerifyFile(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct     = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
            pcwszFilePath = filePath,
            hFile        = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
        Marshal.StructureToPtr(fileInfo, pFile, false);

        var data = new WINTRUST_DATA
        {
            cbStruct            = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
            dwUIChoice          = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice       = WTD_CHOICE_FILE,
            pFile               = pFile,
            dwStateAction       = WTD_STATEACTION_VERIFY,
        };

        uint result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);

        // Close the state
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);

        Marshal.FreeHGlobal(pFile);
        return result == ERROR_SUCCESS;
    }

    /// <summary>Gets the signer subject from an embedded certificate, without trust verification.</summary>
    public static string GetSignerSubject(string filePath)
    {
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
            return cert.Subject;
        }
        catch (System.Exception) { return ""; }
    }

    /// <summary>
    /// Returns the signer certificate's public DER bytes. No private material
    /// exists in an Authenticode signature. Empty on unsupported/invalid input.
    /// </summary>
    public static byte[] GetSignerCertificateRawData(string filePath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(filePath))
            return Array.Empty<byte>();
        try
        {
            using var legacy = X509Certificate.CreateFromSignedFile(filePath);
            using var certificate = new X509Certificate2(legacy);
            return certificate.Export(X509ContentType.Cert);
        }
        catch (Exception)
        {
            return Array.Empty<byte>();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BETA 11A — catalog-aware signature verification.
    //
    // Embedded Authenticode is tried FIRST and unchanged. Only when a file has no
    // valid embedded signature do we consult the Windows security catalogs (where
    // most OS components — System32/WinSxS — are actually signed). A catalog match
    // grants "signed" ONLY when WinVerifyTrust succeeds on the catalog; a missing
    // catalog, a failed lookup, or any exception yields Unsigned (never trust).
    // The signer subject is read from the catalog file itself (it is Authenticode-
    // signed) and flows through the SAME publisher/reputation relief paths as an
    // embedded signer — no scoring, threshold, or anti-FP change here.
    // ─────────────────────────────────────────────────────────────────────────

    // Test seams (BETA 11A). Default null → real native behavior. They let unit
    // tests drive the embedded/catalog orchestration deterministically without a
    // real signed file or native catalog database. Reset to null after each test.
    internal static Func<string, bool>? EmbeddedProbeOverride;
    internal static Func<string, string>? EmbeddedSubjectOverride;
    internal static Func<string, SignatureVerificationResult?>? CatalogProbeOverride;

    /// <summary>
    /// Verify a file's signature, preferring embedded Authenticode and falling back
    /// to Windows security catalogs. Never throws; returns
    /// <see cref="SignatureVerificationResult.Unsigned"/> on any failure.
    ///
    /// <paramref name="allowCatalog"/> (default true) gates the expensive catalog
    /// fallback. The caller passes false for files that cannot be catalog-signed
    /// (everything outside genuine OS locations), avoiding a full second file
    /// re-read + catalog-store search per file. Embedded Authenticode is always
    /// checked regardless.
    /// </summary>
    public static SignatureVerificationResult VerifySignature(string filePath, bool allowCatalog = true)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return SignatureVerificationResult.Unsigned;

        // 1. Embedded Authenticode FIRST (existing behavior, unchanged).
        bool embedded;
        try { embedded = EmbeddedProbeOverride?.Invoke(filePath) ?? VerifyFile(filePath); }
        catch (Exception) { embedded = false; }
        if (embedded)
        {
            string subject;
            try { subject = EmbeddedSubjectOverride?.Invoke(filePath) ?? GetSignerSubject(filePath); }
            catch (Exception) { subject = ""; }
            byte[] certificateRawData;
            try { certificateRawData = GetSignerCertificateRawData(filePath); }
            catch (Exception) { certificateRawData = Array.Empty<byte>(); }
            return new SignatureVerificationResult
            {
                IsSigned = true,
                SignerSubject = subject,
                Source = SignatureSource.Embedded,
                SignerCertificateRawData = certificateRawData,
            };
        }

        // Embedded verification did not succeed. Detect whether a signature is PRESENT
        // (a readable certificate blob) but unverified, so the trust model can tell
        // "invalid" apart from "unsigned". This never grants relief either way.
        bool presentButUnverified;
        try { presentButUnverified = !string.IsNullOrEmpty(EmbeddedSubjectOverride?.Invoke(filePath) ?? GetSignerSubject(filePath)); }
        catch (Exception) { presentButUnverified = false; }

        // 2. Windows security catalog fallback. Trust ONLY on a valid catalog verify, and ONLY
        // when the caller allows it (catalog signatures apply to OS components; skipping the probe
        // for non-system files avoids a per-file file re-read + catalog-store search).
        if (allowCatalog)
        {
            try
            {
                var catalog = CatalogProbeOverride != null
                    ? CatalogProbeOverride(filePath)
                    : VerifyViaCatalog(filePath);
                if (catalog is { IsSigned: true }) return catalog;
            }
            catch (Exception)
            {
                // A catalog lookup/verification failure must never create trust.
            }
        }

        return new SignatureVerificationResult
        {
            IsSigned = false,
            Source = SignatureSource.None,
            SignaturePresentButUnverified = presentButUnverified,
        };
    }

    private const uint WTD_CHOICE_CATALOG = 2;

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint   cbStruct;
        public uint   dwCatalogVersion;
        public string pcwszCatalogFilePath;
        public string pcwszMemberTag;
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint   cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    /// <summary>
    /// Native catalog verification. Windows-only; returns Unsigned on non-Windows,
    /// on any missing/failed catalog, or on any exception. Releases all catalog and
    /// admin handles in <c>finally</c>.
    /// </summary>
    private static SignatureVerificationResult VerifyViaCatalog(string filePath)
    {
        if (!OperatingSystem.IsWindows()) return SignatureVerificationResult.Unsigned;

        IntPtr hCatAdmin = IntPtr.Zero, hCatInfo = IntPtr.Zero;
        IntPtr pHash = IntPtr.Zero, pCatalogInfo = IntPtr.Zero;
        FileStream? fs = null;
        try
        {
            if (!CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0) || hCatAdmin == IntPtr.Zero)
                return SignatureVerificationResult.Unsigned;

            fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashLen = 0;
            // First call (null buffer) reports the required hash length via hashLen.
            CryptCATAdminCalcHashFromFileHandle(hFile, ref hashLen, null, 0);
            if (hashLen == 0) return SignatureVerificationResult.Unsigned;
            var hash = new byte[hashLen];
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref hashLen, hash, 0))
                return SignatureVerificationResult.Unsigned;

            IntPtr prev = IntPtr.Zero;
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, ref prev);
            if (hCatInfo == IntPtr.Zero) return SignatureVerificationResult.Unsigned; // not catalog-signed

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0) || string.IsNullOrEmpty(ci.wszCatalogFile))
                return SignatureVerificationResult.Unsigned;

            pHash = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, pHash, hash.Length);

            var wci = new WINTRUST_CATALOG_INFO
            {
                cbStruct             = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion     = 0,
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag       = Convert.ToHexString(hash),
                pcwszMemberFilePath  = filePath,
                hMemberFile          = hFile,
                pbCalculatedFileHash = pHash,
                cbCalculatedFileHash = hashLen,
                pcCatalogContext     = IntPtr.Zero,
                hCatAdmin            = hCatAdmin,
            };
            pCatalogInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(wci, pCatalogInfo, false);

            var data = new WINTRUST_DATA
            {
                cbStruct            = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice          = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice       = WTD_CHOICE_CATALOG,
                pFile               = pCatalogInfo,   // union member; catalog info for WTD_CHOICE_CATALOG
                dwStateAction       = WTD_STATEACTION_VERIFY,
            };

            uint result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);

            if (result != ERROR_SUCCESS) return SignatureVerificationResult.Unsigned;

            // The catalog file is itself Authenticode-signed; reuse the embedded
            // subject extraction to surface the catalog signer (e.g. Microsoft).
            string subject;
            try { subject = GetSignerSubject(ci.wszCatalogFile); }
            catch (Exception) { subject = ""; }
            byte[] certificateRawData;
            try { certificateRawData = GetSignerCertificateRawData(ci.wszCatalogFile); }
            catch (Exception) { certificateRawData = Array.Empty<byte>(); }

            return new SignatureVerificationResult
            {
                IsSigned = true,
                SignerSubject = subject,
                Source = SignatureSource.Catalog,
                SignerCertificateRawData = certificateRawData,
            };
        }
        catch (Exception)
        {
            return SignatureVerificationResult.Unsigned;
        }
        finally
        {
            if (pCatalogInfo != IntPtr.Zero) Marshal.FreeHGlobal(pCatalogInfo);
            if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
            fs?.Dispose();
        }
    }
}
