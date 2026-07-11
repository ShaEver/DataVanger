# DataVanger Service Recovery Runbook (P0 safety gate)

The service installer is **unavailable until a secure installer is implemented and reviewed**.
`--install` always exits with code `7` before elevation checks, path resolution, copying, service
registration, or process execution. Do not register the service manually from a build, Downloads,
Temp, or another user-writable directory.

The WPF UI remains non-elevated. `--status`, `--validate-config`, and `--console` do not create a
persistent installation. `--service` remains an explicit host mode for development, but this build
does not install it with the Service Control Manager.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | recovery succeeded or the service was already absent |
| 3 | recovery is unsupported on this platform |
| 4 | recovery requires an elevated Windows prompt; no silent elevation |
| 5 | the underlying recovery operation failed |
| 7 | secure installer unavailable; installation blocked before any external process runs |

## Safe validation and recovery

```powershell
# Safe status commands; no persistent installation.
.\DataVanger.Service.exe --status
.\DataVanger.Service.exe --validate-config

# Blocked from both normal and elevated prompts.
.\DataVanger.Service.exe --install
# Expected: exit 7 and "unavailable until a secure installer"; sc.exe is not run.

# Elevated recovery only, if an older build registered the service.
.\DataVanger.Service.exe --uninstall
.\DataVanger.Service.exe --uninstall
# Both cleanup calls are successful; the second reports that the service is already absent.
```

## Requirements before reactivation

Reactivation requires a separately reviewed installer that:

- stages signed artifacts under a fixed protected installation root;
- verifies publisher, thumbprint, ownership, and ACLs before registration;
- rejects relative, UNC, ADS, traversal, reparse, and user-writable paths;
- keeps configuration under the protected root;
- provisions a dedicated or virtual least-privilege service account;
- performs an immediate final validation before the SCM change.

`PrivilegedInstallationSecurityPolicy.cs` defines a testable future policy boundary. It does not
provide production ACL/AuthentiCode probes, copy files, elevate, or make installation available.
