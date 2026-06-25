# DataVanger Service Activation Runbook (Beta 02A)

Operator guide for activating, verifying and removing the `DataVangerService` Windows service —
the future privileged remediation backend. The WPF UI always remains **non-elevated**; the only
admin-gated operations are the explicit service `--install` / `--uninstall` commands.

**This service exposes NO remediation capability.** Its IPC surface is status, configuration
summary, protection pause/resume plumbing, scan, quarantine list/details/restore (delete returns
`Unsupported`), update status, event query, and diagnostics. Destructive commands arrive only
after the `02B` IPC ACL gate and the `03`/`04` remediation phases.

## 1. Identity and configuration (registered by `--install`)

| Item | Value |
|------|-------|
| Service name | `DataVangerService` |
| Display name | `DataVanger Security Service` |
| Startup type | **demand** (manual) — never auto-started by installation |
| Recovery | restart on 1st/2nd/3rd failure, 60 s apart; failure counter reset after 86 400 s (1 day) |
| Binary path | absolute apphost next to the entry assembly, `"<dir>\DataVanger.Service.exe" --service` (+ optional `--config "<abs path>"`) |
| Registration | `sc.exe` with structured argument lists (`UseShellExecute=false`) — no shell, no injection surface |
| Elevation | admin-gated; **fails closed** with exit 4 when not elevated; **no silent elevation** |

### Exit codes (`--install` / `--uninstall`)

| Code | Meaning |
|------|---------|
| 0 | success |
| 3 | unsupported platform (non-Windows) — verified live: `--install` on Linux prints "supported only on Windows" and registers nothing |
| 4 | not elevated — clear "re-run from an elevated prompt" error, nothing registered/removed |
| 5 | an underlying `sc.exe` step failed (surfaced, never simulated as success) |
| 6 | **(new in 02A)** invalid service path — install aborts rather than registering a relative, PATH-resolved (`dotnet`), missing or empty executable path |

## 2. Manual Windows validation procedure (mandatory for phase sign-off)

From the published/built output directory (`DataVanger.Service\bin\...` or publish folder):

```powershell
# 1. Status BEFORE install (no service yet; snapshot is the in-process runtime)
.\DataVanger.Service.exe --status            # expect structured snapshot, Development mode
sc.exe query DataVangerService               # expect: service does not exist (1060)

# 2. Non-elevated install attempt (from a NORMAL prompt) — must fail closed
.\DataVanger.Service.exe --install           # expect exit 4, admin-required message

# 3. Install from an ELEVATED prompt
.\DataVanger.Service.exe --install           # expect exit 0, "NOT started" notice

# 4. Verify registration (path, start type, recovery)
sc.exe qc DataVangerService                  # BINARY_PATH_NAME = absolute quoted apphost + --service
                                             # START_TYPE = 3 DEMAND_START
sc.exe qfailure DataVangerService            # RESET_PERIOD 86400; 3x RESTART/60000

# 5. Start/stop round-trip (safe; runtime hosts non-destructive handlers only)
sc.exe start DataVangerService
sc.exe query DataVangerService               # RUNNING
.\DataVanger.Service.exe --status
sc.exe stop  DataVangerService               # must accept control (apphost registration)

# 6. Uninstall from an ELEVATED prompt
.\DataVanger.Service.exe --uninstall         # expect exit 0 (stop is best-effort, then delete)
sc.exe query DataVangerService               # expect 1060 again

# 7. UI elevation check
# Launch DataVanger.exe from a NORMAL prompt: no UAC prompt may appear; the
# app runs fully as a standard user (Task Manager → Details → Elevated = No).
```

Record each output in the phase validation notes.

## 3. Diagnostics without destructive surface

- `--status` / `--validate-config` / `--console` never install, mutate, or start anything persistent.
- Default invocation prints a banner and exits — safe for accidental execution.
- IPC status/diagnostics queries are read-only; `DeleteQuarantineItem` honestly returns
  `Unsupported` (verified by `~ServiceActivationReview` tests).

## 4. Known gaps handed to 02B_IPC_ACL_SECURITY_GATE

1. **No Windows ACL on the named pipe.** `NamedPipeDataVangerServiceHost` validates payloads
   (allowlist + size bounds) but creates the pipe without a `PipeSecurity` descriptor — any local
   user can connect. Must be restricted (current user + SYSTEM/Administrators) before the service
   gains any privileged command.
2. **No client identity logging.** Pipe connections are not attributed to a calling identity;
   02B should add caller identification to the audit trail.
3. **Single-instance pipe serving** (`ProcessNextAsync` one connection at a time) — acceptable
   now; revisit under 02B if concurrent UI + tooling access is needed.
4. **ETW gate ships off by default** (`--validate-config` live output: `etw-runtime-telem: False`);
   activation remains config-opt-in via `--install --config <path>` — unchanged in this phase.
