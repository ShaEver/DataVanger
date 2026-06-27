using System;
using System.Collections.Generic;
using DataVanger.Shared.Behavioral.Runtime;

namespace DataVanger.Engine.Behavioral.Runtime;

/// <summary>
/// Conservative runtime behavior rule evaluator for the Behavioral Engine
/// Runtime Binding (Phase 2 / Step 06).
///
/// This is a runtime-telemetry-specific rule evaluator. It is NOT a
/// replacement for, and does NOT compete with, the existing scan-time
/// Behavioral Engine (which operates on PE / static analysis). It only
/// evaluates short-lived runtime process/command/lineage context.
///
/// CRITICAL anti-false-positive guarantees:
///   - Every rule emits <see cref="BehavioralRuntimeEvidence"/> which is
///     evidence ONLY (its severity tops out at HighRisk and it can never
///     be ConfirmedMalware).
///   - Rules are context-sensitive; benign LOLBin / interpreter usage
///     produces no high-risk evidence.
///   - No rule quarantines, kills, suspends, blocks, or injects.
/// </summary>
public sealed class BehavioralRuntimeRuleEvaluator
{
    private readonly BehavioralRuntimeBindingOptions _options;
    private readonly BehavioralRuntimeEvidenceFactory _factory;

    public BehavioralRuntimeRuleEvaluator(
        BehavioralRuntimeBindingOptions options,
        BehavioralRuntimeEvidenceFactory? factory = null)
    {
        _options = (options ?? new BehavioralRuntimeBindingOptions()).WithSafeDefaults();
        _factory = factory ?? new BehavioralRuntimeEvidenceFactory();
    }

    /// <summary>
    /// Evaluates all enabled rules for a single observation. Never throws;
    /// returns an empty list when nothing matches.
    /// </summary>
    public IReadOnlyList<BehavioralRuntimeEvidence> Evaluate(
        BehavioralRuntimeObservation observation,
        BehavioralCorrelationState? correlationState)
    {
        if (observation is null) return Array.Empty<BehavioralRuntimeEvidence>();

        var results = new List<BehavioralRuntimeEvidence>();
        try
        {
            var childName = ResolveChildName(observation);
            var (parentName, parentPath) = ResolveParent(observation, correlationState);

            EvaluateOfficeSpawnsInterpreter(observation, childName, parentName, parentPath, results);
            EvaluatePowerShell(observation, parentName, parentPath, results);
            EvaluateLolBin(observation, childName, parentName, parentPath, results);
            EvaluateRiskyPath(observation, childName, parentName, parentPath, results);
            EvaluatePersistence(observation, parentName, parentPath, results);
            EvaluateTamper(observation, parentName, parentPath, results);
        }
        catch (System.Exception)
        {
            // A rule failure must never crash the binding. Drop partial
            // results conservatively and return what we have.
        }

        return results;
    }

    // Rule 1 — Office spawning a script interpreter.
    private void EvaluateOfficeSpawnsInterpreter(
        BehavioralRuntimeObservation o, string? childName, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnableProcessLineageCorrelation) return;
        if (o.Kind != BehavioralObservationKind.ProcessStart) return;
        if (!BehavioralRuntimeProcessCatalog.IsScriptInterpreter(childName)) return;
        if (!BehavioralRuntimeProcessCatalog.IsOfficeProcess(parentName)) return;

        results.Add(_factory.Create(
            ruleId: "BRB-R1",
            ruleName: "Office process spawned a script interpreter",
            severity: BehavioralRuntimeSeverity.Suspicious,
            confidence: BehavioralRuntimeConfidence.Medium,
            score: 25,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: new List<string> { "office-spawns-interpreter" },
            explanation: $"{parentName} spawned {childName}. Office applications launching script interpreters is a suspicious behavior chain, but this is runtime behavioral evidence only and must not confirm malware without stronger confirmation."));
    }

    // Rule 2 — PowerShell encoded / hidden / dynamic execution.
    private void EvaluatePowerShell(
        BehavioralRuntimeObservation o, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnablePowerShellIndicators) return;
        if (o.Kind is not (BehavioralObservationKind.ProcessStart
            or BehavioralObservationKind.CommandLine
            or BehavioralObservationKind.Script)) return;

        if (!BehavioralCommandLineIndicators.IsPowerShellProcess(o.ProcessName)) return;

        var tags = MergePowerShellTags(o);
        var suspicious = new List<string>();
        if (tags.Contains(BehavioralCommandLineIndicators.TagEncodedCommand)) suspicious.Add(BehavioralCommandLineIndicators.TagEncodedCommand);
        if (tags.Contains(BehavioralCommandLineIndicators.TagHiddenWindow)) suspicious.Add(BehavioralCommandLineIndicators.TagHiddenWindow);
        if (tags.Contains(BehavioralCommandLineIndicators.TagDynamicExecution)) suspicious.Add(BehavioralCommandLineIndicators.TagDynamicExecution);
        if (tags.Contains(BehavioralCommandLineIndicators.TagPolicyBypass)) suspicious.Add(BehavioralCommandLineIndicators.TagPolicyBypass);

        if (suspicious.Count == 0) return; // benign PowerShell — no evidence.

        var severity = suspicious.Count >= 2 ? BehavioralRuntimeSeverity.HighRisk : BehavioralRuntimeSeverity.Suspicious;
        var confidence = suspicious.Count >= 2 ? BehavioralRuntimeConfidence.High : BehavioralRuntimeConfidence.Medium;
        var score = Math.Min(15 + suspicious.Count * 7, 45);

        var indicators = new List<string> { BehavioralCommandLineIndicators.TagPowerShellProcess };
        indicators.AddRange(suspicious);

        results.Add(_factory.Create(
            ruleId: "BRB-R2",
            ruleName: "Suspicious PowerShell execution indicators",
            severity: severity,
            confidence: confidence,
            score: score,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: indicators,
            explanation: $"PowerShell command line carried suspicious execution indicators ({string.Join(", ", suspicious)}). This is runtime behavioral evidence only and must not confirm malware without stronger confirmation."));
    }

    // Rule 3 — LOLBin suspicious chain (context-sensitive).
    private void EvaluateLolBin(
        BehavioralRuntimeObservation o, string? childName, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnableLolBinIndicators) return;
        if (o.Kind is not (BehavioralObservationKind.ProcessStart or BehavioralObservationKind.CommandLine)) return;
        if (!BehavioralRuntimeProcessCatalog.IsLolBin(childName)) return;

        // Require a suspicious context — do NOT flag benign LOLBin usage.
        var suspiciousArgs = BehavioralCommandLineIndicators.HasSuspiciousLolBinArguments(o.CommandLine);
        var suspiciousParent = BehavioralRuntimeProcessCatalog.IsOfficeProcess(parentName);
        if (!suspiciousArgs && !suspiciousParent) return;

        var context = new List<string> { "lolbin" };
        if (suspiciousArgs) context.Add(BehavioralCommandLineIndicators.TagLolBinSuspiciousArgs);
        if (suspiciousParent) context.Add("lolbin-office-parent");

        // Conservative: a single weak context is Suspicious, never HighRisk.
        var severity = (suspiciousArgs && suspiciousParent)
            ? BehavioralRuntimeSeverity.HighRisk
            : BehavioralRuntimeSeverity.Suspicious;
        var confidence = (suspiciousArgs && suspiciousParent)
            ? BehavioralRuntimeConfidence.High
            : BehavioralRuntimeConfidence.Medium;
        var score = (suspiciousArgs && suspiciousParent) ? 35 : 20;

        results.Add(_factory.Create(
            ruleId: "BRB-R3",
            ruleName: "Suspicious LOLBin usage in context",
            severity: severity,
            confidence: confidence,
            score: score,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: context,
            explanation: $"{childName} was used with suspicious context ({string.Join(", ", context)}). Living-off-the-land binaries are legitimate tools; this is runtime behavioral evidence only and must not confirm malware without stronger confirmation."));
    }

    // Rule 4 — Executable launched from a user-writable risky path.
    private void EvaluateRiskyPath(
        BehavioralRuntimeObservation o, string? childName, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnableRiskyPathIndicators) return;
        if (o.Kind != BehavioralObservationKind.ProcessStart) return;
        if (!BehavioralRuntimeProcessCatalog.IsRiskyExecutablePath(o.ImagePath)) return;

        // Combined context bumps severity but never beyond Suspicious here.
        var officeParent = BehavioralRuntimeProcessCatalog.IsOfficeProcess(parentName);
        var hasPsIndicators = MergePowerShellTags(o).Count > 1; // more than just the process tag
        var combined = officeParent || hasPsIndicators;

        var severity = combined ? BehavioralRuntimeSeverity.Suspicious : BehavioralRuntimeSeverity.Low;
        var confidence = combined ? BehavioralRuntimeConfidence.Medium : BehavioralRuntimeConfidence.Low;
        var score = combined ? 20 : 8;

        var indicators = new List<string> { "executable-from-risky-path" };
        if (officeParent) indicators.Add("risky-path-office-parent");

        results.Add(_factory.Create(
            ruleId: "BRB-R4",
            ruleName: "Executable launched from user-writable risky path",
            severity: severity,
            confidence: confidence,
            score: score,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: indicators,
            explanation: $"{childName} started from a user-writable risky path ({o.ImagePath}). Many legitimate installers use such paths; this is low/medium runtime behavioral evidence only and must not confirm malware without stronger confirmation."));
    }

    // Rule 5 — Persistence attempt observed (consume only; do not implement monitoring).
    private void EvaluatePersistence(
        BehavioralRuntimeObservation o, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnablePersistenceIndicators) return;
        if (o.Kind != BehavioralObservationKind.Persistence) return;

        results.Add(_factory.Create(
            ruleId: "BRB-R5",
            ruleName: "Persistence activity observed",
            severity: BehavioralRuntimeSeverity.Suspicious,
            confidence: BehavioralRuntimeConfidence.Medium,
            score: 25,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: new List<string> { "persistence-observed" },
            explanation: $"Persistence-related activity was observed (subject: {o.SubjectPath ?? "<unknown>"}). This is runtime behavioral evidence only and must not confirm malware without stronger confirmation."));
    }

    // Rule 6 — Security tamper attempt observed (tamper evidence only).
    private void EvaluateTamper(
        BehavioralRuntimeObservation o, string? parentName, string? parentPath,
        List<BehavioralRuntimeEvidence> results)
    {
        if (!_options.EnableTamperIndicators) return;
        if (o.Kind != BehavioralObservationKind.Tamper) return;

        results.Add(_factory.Create(
            ruleId: "BRB-R6",
            ruleName: "Security tamper activity observed",
            severity: BehavioralRuntimeSeverity.Suspicious,
            confidence: BehavioralRuntimeConfidence.Medium,
            score: 30,
            observation: o,
            parentProcessName: parentName,
            parentProcessPath: parentPath,
            indicators: new List<string> { "tamper-observed" },
            explanation: $"Security-tamper activity was observed (subject: {o.SubjectPath ?? "<unknown>"}). This is tamper evidence only and must not confirm malware by itself."));
    }

    private static string? ResolveChildName(BehavioralRuntimeObservation o)
    {
        if (!string.IsNullOrWhiteSpace(o.ProcessName)) return BehavioralRuntimeProcessCatalog.Normalize(o.ProcessName);
        if (!string.IsNullOrWhiteSpace(o.ImagePath)) return BehavioralRuntimeProcessCatalog.Normalize(o.ImagePath);
        return null;
    }

    private static (string? name, string? path) ResolveParent(
        BehavioralRuntimeObservation o, BehavioralCorrelationState? state)
    {
        string? name = string.IsNullOrWhiteSpace(o.ParentProcessName)
            ? null
            : BehavioralRuntimeProcessCatalog.Normalize(o.ParentProcessName);
        string? path = o.ParentImagePath;

        if (name is null && o.ParentProcessId is int ppid && state is not null && state.TryGet(ppid, out var parent))
        {
            if (!string.IsNullOrWhiteSpace(parent.ProcessName)) name = BehavioralRuntimeProcessCatalog.Normalize(parent.ProcessName);
            else if (!string.IsNullOrWhiteSpace(parent.ImagePath)) name = BehavioralRuntimeProcessCatalog.Normalize(parent.ImagePath);
            path ??= parent.ImagePath;
        }

        return (name, path);
    }

    private static HashSet<string> MergePowerShellTags(BehavioralRuntimeObservation o)
    {
        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in o.Indicators) tags.Add(t);
        foreach (var t in BehavioralCommandLineIndicators.DetectPowerShellIndicators(o.ProcessName, o.CommandLine)) tags.Add(t);
        return tags;
    }
}
