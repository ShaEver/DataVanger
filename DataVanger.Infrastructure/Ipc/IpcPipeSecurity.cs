using System;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DataVanger.Infrastructure.Ipc;

/// <summary>
/// Builds a least-privilege Windows security descriptor (DACL) for the local
/// named-pipe IPC host and creates the ACL-protected server stream.
///
/// Responsibility boundary (defense-in-depth, NOT a replacement):
///   - This type controls WHO may connect to the pipe (connection-level ACL).
///   - <see cref="IpcSecurityPolicy"/> controls WHAT a connected caller may
///     request (command allowlist, bounded size, safe-path rules).
///   - <c>NamedPipeFraming</c> controls message size/framing.
///   - <c>IpcSerialization</c> controls defensive deserialization.
/// All four layers remain active and independent; none is weakened by this one.
///
/// Default-deny model:
///   - A fresh DACL is built that GRANTS access only to explicitly allowed local
///     principals. Every principal not granted is denied by omission.
///   - The Network logon SID is additionally DENIED for defense-in-depth, so a
///     remote/network logon can never connect even if it were a member of an
///     allowed group. Local pipe clients are not network logons, so this does
///     not block legitimate local callers.
///   - Everyone and Anonymous are never granted.
///
/// All members that touch a security descriptor are Windows-only (Windows ACLs).
/// On non-Windows the host falls back to a plain <see cref="NamedPipeServerStream"/>;
/// callers must check <see cref="IsSupported"/> first.
/// </summary>
public static class IpcPipeSecurity
{
    /// <summary>True only on Windows, where named-pipe security descriptors exist.</summary>
    public static bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>
    /// Builds the least-privilege DACL for the IPC pipe from the given options.
    /// Grants the creating user and Local System; denies Network; adds any valid
    /// configured principals as read/write clients. Invalid configured entries
    /// are ignored (a parse failure must never broaden access).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static PipeSecurity Build(IpcOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var security = new PipeSecurity();

        // Defense-in-depth: explicitly deny network logons. Deny ACEs are
        // evaluated before allow ACEs, so this cannot be overridden by a later
        // grant. A local pipe client is never a network logon.
        var networkSid = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        security.AddAccessRule(new PipeAccessRule(
            networkSid, PipeAccessRights.FullControl, AccessControlType.Deny));

        // Allow the creating principal full control so it can create pipe
        // instances and serve requests.
        var currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is not null)
        {
            security.AddAccessRule(new PipeAccessRule(
                currentUser, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        // Allow Local System — the expected privileged service identity.
        var localSystem = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.AddAccessRule(new PipeAccessRule(
            localSystem, PipeAccessRights.FullControl, AccessControlType.Allow));

        // Allow explicitly configured local principals as read/write clients only.
        foreach (var principal in options.AllowedPrincipalSids)
        {
            if (TryResolveSid(principal, out var sid)
                && sid is not null
                && !IsForbiddenPrincipal(sid))
            {
                security.AddAccessRule(new PipeAccessRule(
                    sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            }
            // Else: ignored on purpose. A malformed/unresolvable principal — or a
            // forbidden broad/remote principal (Everyone/Anonymous/Network/Guests)
            // — must NEVER fall back to a broader allow rule.
        }

        return security;
    }

    /// <summary>
    /// True for broad or remote principals that must never be granted connect
    /// access, even when explicitly configured. Blocks Everyone (S-1-1-0),
    /// Anonymous (S-1-5-7), Network (S-1-5-2), and Guests (S-1-5-32-546).
    /// Configured entries that resolve to any of these are silently dropped.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool IsForbiddenPrincipal(SecurityIdentifier sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        return sid.IsWellKnown(WellKnownSidType.WorldSid)          // Everyone   S-1-1-0
            || sid.IsWellKnown(WellKnownSidType.AnonymousSid)      // Anonymous  S-1-5-7
            || sid.IsWellKnown(WellKnownSidType.NetworkSid)        // Network    S-1-5-2
            || sid.IsWellKnown(WellKnownSidType.BuiltinGuestsSid); // Guests     S-1-5-32-546
    }

    /// <summary>
    /// Creates a named-pipe server stream protected by the least-privilege DACL
    /// from <see cref="Build"/>. Pipe name, direction, instance cap, transmission
    /// mode, and options match the plain (non-ACL) host construction exactly.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static NamedPipeServerStream CreateServerStream(IpcOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var security = Build(options);
        return NamedPipeServerStreamAcl.Create(
            options.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            pipeSecurity: security);
    }

    /// <summary>
    /// Resolves a principal expressed as an SDDL SID string ("S-1-5-...") or a
    /// local account name to a <see cref="SecurityIdentifier"/>. Returns false on
    /// any malformed/unresolvable input so the caller can skip it without
    /// broadening access.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool TryResolveSid(string? value, out SecurityIdentifier? sid)
    {
        sid = null;
        if (string.IsNullOrWhiteSpace(value)) return false;

        var text = value.Trim();
        try
        {
            if (text.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            {
                sid = new SecurityIdentifier(text);
                return true;
            }

            var account = new NTAccount(text);
            sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
            return true;
        }
        catch (ArgumentException)
        {
            return false; // malformed SDDL / account string
        }
        catch (IdentityNotMappedException)
        {
            return false; // account name could not be resolved to a SID
        }
    }
}
