# DataVanger V.Alpha — Operator Guide

Audience: operators/end users running DataVanger on Windows. This guide describes
**current code behavior** and explicitly marks what is **Active**, **Prepared**,
**Fallback**, **Stubbed**, or **requires approval before activation**.

> Platform: Windows + .NET 8 runtime. The UI (`DataVanger`) and service
> (`DataVanger.Service`) target `net8.0-windows`.

---

## 1. How to run the app

- **Desktop UI:** build and run `DataVanger/DataVanger.csproj` (WinExe). The main
  window provides scan controls, results/review, quarantine, and settings.
- **Service host (diagnostic only):** `DataVanger.Service` exposes CLI modes:
  - `--console` — run interactively in console mode
  - `--status` — print a status snapshot and exit
  - `--validate-config` — load configuration and print warnings
  - `--help` — usage
  - `--service` — **STUB**: prints *"--service is a diagnostic stub in this phase; no
    Windows Service was installed."* (`DataVanger.Service/Program.cs`). No real
    Windows service is registered.

## 2. Settings overview

Settings live in `AppSettings` (`DataVanger/Core/AppSettings.cs`) and are edited via
the Settings window (`DataVanger/SettingsWindow.xaml(.cs)`). `TrustedPublishers`
(the curated base trusted-publisher list) is
intentionally **not** UI-exposed — operators add their own via
**`ExtraTrustedPublishers`** ("Publishers confiáveis extras"). Key settings:

- **Scan targets / exclusions:** `ExtraTargets`, `ExcludedPaths`, plus the
  Scan-Downloads/Desktop/Documents/AppData/Startup toggles and `IncludeRemovableDrives`.
- **Thresholds:** `MinScoreToReport` (default 6 = Suspect), `MinScoreToQuarantine`
  (default 9 = High).
- **Quarantine:** `AutoQuarantineKnownMalware` (auto-quarantine applies **only** to
  ConfirmedMalware regardless of this toggle's convenience role).
- **YARA:** `EnableYaraRules`, `YaraMaxScanSizeMB`.
- **Archives:** `DeepScanArchives`, `ArchiveMaxEntries/Depth/DecompressedMB`.
- **Analyzers:** Documents, BrowserExtensions, AlternateDataStreams, Persistence,
  Services/Drivers, ScheduledTasks.
- **Trusted publishers (extra):** `ExtraTrustedPublishers` — merged on top of the
  built-in safe defaults. A trusted publisher **never** overrides a malicious hash.
- **`EnableTrayProtection`** (default off). Atualizações usam somente o feed assinado;
  `SignatureUpdateUrl` foi desativada e não é migrada para o feed confiável.

## 3. Scan behavior

The on-demand/scheduled scan runs through `ScanEngine` (`DataVanger/Core/ScanEngine.cs`)
in five phases: load configuration → collect global context → index eligible files →
run detection → commit results (reports + persisted state). Each file passes through
the detection pipeline (hash, heuristics, script, PE incl. **per-section entropy**,
archive, document, browser-extension, YARA, persistence), then reputation scoring,
then the **anti-false-positive clamp**.

**What a verdict means:**
- **ConfirmedMalware** — only from a blacklisted (known-malicious) hash or evidence
  explicitly able to confirm (e.g. a curated `confirmed` lightweight YARA rule).
- **HighRisk** — heuristic-only signals are clamped here; they are **not** confirmation.
- Lower tiers (Suspect/Clean) are reported per thresholds.

## 4. Quarantine and restore behavior — **Active (Quarantine V2)**

- Implementation: `DataVanger.Engine/Quarantine/QuarantineService.cs` with
  `DataVanger.Infrastructure/Quarantine/FileSystemQuarantineStore.cs` and
  `DpapiQuarantineKeyProtector.cs`, composed once by
  `DataVanger/Infrastructure/QuarantineCompositionRoot.cs`.
- The key is protected with Windows DPAPI **CurrentUser** and is owned by the
  interactive UI user. `QuarantineCompositionRoot.KeyAuthority` makes this authority
  explicit: a future LocalSystem owner must expose operations through IPC and perform a
  reviewed protected-key migration; copying the master key in plaintext is forbidden.
- Source hashing/encryption uses one stable handle. Reparse ancestors are refused and
  original removal verifies Windows volume/file identity, preserving a substituted file.
- Restore uses exclusive temp creation, durable flush and atomic no-overwrite rename;
  destination races and reparse changes have distinct statuses.
- The current single-chunk AES-GCM payload format is capped at 16 MiB plaintext. Larger
  files fail closed until a separately versioned authenticated chunked format exists.
- Payloads are authenticated-encrypted; metadata is HMAC-protected; the original
  SHA-256 is recorded and re-verified on restore.
- **Automatic quarantine occurs only for `ConfirmedMalware`** (plus the score gate);
  heuristic findings are never auto-quarantined.
- **Restore is never automatic.** It verifies payload + metadata integrity and the
  original hash before writing back, and emits an audit event. A tampered record
  refuses restore.
- Restore refuses overwrite, traversal, ADS, quarantine/runtime/program roots, and
  unauthenticated metadata. Audit events are appended as structured JSON Lines.
- Legacy V1 payloads/indexes are treated as unauthenticated. The UI only reports
  their presence and directs the operator to isolated manual cleanup; it never
  decrypts them or restores them to `OriginalPath`.

## 5. Scheduler behavior — **Active**

- `DataVanger/Scheduling/*` provides a deterministic, tick-driven scheduler (advanced
  by the host/UI/clock, not a background thread). It orchestrates scheduled scans and
  persists job state; it never classifies findings itself.

## 6. Realtime protection behavior — **Prepared (conservative engine implemented)**

- `DataVanger.Engine/Realtime/ConservativeRealtimeDecisionEngine.cs` +
  `DataVanger.Service/Realtime/RealtimeProtectionService.cs` implement watcher
  lifecycle, debounce, a bounded queue, and a **conservative** decision policy:
  - Clean/Indeterminate/failed scan → observe only (not authorized)
  - Suspicious → notify; HighRisk → recommend manual review
  - **ConfirmedMalware → quarantine, authorized only when not in passive mode**
- Realtime telemetry **never** becomes a verdict by itself. Running this as a
  privileged background service depends on the (stubbed) Windows service.

## 7. Update behavior — **signed-only, fail-closed**

- Signed-update **verification** is implemented
  (`DataVanger.Engine/Updates/SignedUpdates/SignedUpdateService.cs`,
  `SignedManifestVerifier.cs`): RSA-PSS-SHA256 / ECDsa-P256-SHA256, anti-downgrade via
  sequence numbers, pinned keys. File and in-memory transports work.
- `HttpUpdateTransport` é HTTPS-only, rejeita redirects e aplica limites de tempo/tamanho.
  O transporte só é construído depois que URL HTTPS, feed id, key id, algoritmo e chave
  pinada estão presentes. Configuração incompleta faz zero requests e zero writes.
- Não existe fallback não assinado. Falhas de assinatura, pacote ou sequência preservam
  as assinaturas já ativas/last-known-good.
- PEM em `appsettings.json` é modo development/operator, não uma raiz de confiança de
  produção. Produção aguarda chave vendor embutida ou store administrativo autenticado.

## 8. Service / IPC behavior — **IPC Active (local, payload-validated); ACLs needs hardening; service Stub**

- IPC is local **named pipes**
  (`DataVanger.Infrastructure/Ipc/NamedPipeDataVangerServiceHost.cs` / `Client`) with
  `IpcSecurityPolicy` (request allowlist, bounded message size, safe-path rules) and
  defensive serialization. The service routes commands
  (Scan/Quarantine/Update/Status/Protection/Diagnostics) via
  `DataVanger.Service/Ipc/*`.
- **No Windows ACL / security descriptor restriction is applied yet** — the host
  comment notes "Future ACL hardening (PipeSecurity) can be added". Treat IPC as
  local-only and **needs hardening** before exposure on multi-user machines.
- The Windows **service itself is a stub** (`--service`), so realtime protection does
  not yet run as a privileged background service.

## 9. What is Active

On-demand/scheduled file scanning, detection pipeline (hash/heuristic/script/PE+entropy/
archive/document/browser-extension/YARA/persistence), reputation scoring, anti-FP
classification, configurable trusted publishers, lightweight YARA engine, Quarantine
V2 (+ DPAPI on Windows), scheduler, signed-update **verification**, local named-pipe
IPC (payload-validated).

## 10. What is Prepared (implemented, not activated)

Real libyara backend (`#if YARA_REAL`), realtime protection service, ETW/AMSI runtime
providers, memory scanner + behavioral correlation engines (present and tested, but
not wired into the per-file scan — see matrix "Needs audit").

## 11. What is Fallback

The **lightweight YARA engine** (`LightweightYaraDatabase` via `YaraEngineAdapter`) is
the guaranteed, always-valid YARA backend used whenever the real libyara backend is
not compiled/available. ETW providers fall back to Null/InMemory when a real session
is unavailable.

## 12. What is Stubbed

`HttpUpdateTransport` (throws), `--service` Windows service mode (diagnostic only),
ETW/AMSI behavior adapters (`IsAvailable=false`).

## 13. What requires explicit approval before activation

Enabling any of the following is an **approval-gated** change and requires Windows
build/runtime validation:

- Real libyara (`dnYara` package + `YARA_REAL`) — must restore/build first.
- Signed-update HTTP transport (opt-in, verify-before-trust).
- Windows service installation / auto-start.
- Named-pipe IPC ACL restriction.
- Real ETW / AMSI providers (privileged, bounded).

None of these change the anti-false-positive contract: heuristics, entropy, real
external YARA, behavioral/ETW/AMSI, publisher trust, service/update/restore failures
**never** confirm malware on their own, and automatic quarantine remains
`ConfirmedMalware`-only.
