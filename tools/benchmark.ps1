#Requires -Version 5.0
<#
.SYNOPSIS
DataVanger Performance Benchmark Harness (Phase 1 Telemetry).

.DESCRIPTION
Executes Full/Deep/Standard scan profiles with detailed telemetry capture.
Compares results against baseline (cold vs warm cache) and generates
comparative analysis for regression detection before/after optimization phases.

.PARAMETER Profile
Scan profile to benchmark: Quick, Standard, Deep, Full. Default: Full.

.PARAMETER Count
Number of consecutive runs (cold + warm cache detection). Default: 1.

.PARAMETER OutputDir
Directory to store telemetry and benchmark results. Default: outputs/benchmarks.

.PARAMETER ConfigPath
Path to DataVanger.exe or config file. Auto-detected if omitted.

.EXAMPLE
.\benchmark.ps1 -Profile Full -Count 2 -OutputDir ./benchmarks

Runs Full Scan twice (cold then warm), saves telemetry and baseline comparison.

.EXAMPLE
.\benchmark.ps1 -Profile Quick -Count 1

Runs Quick Scan once, uses default output directory.
#>
param(
    [ValidateSet("Quick", "Standard", "Deep", "Full")]
    [string]$Profile = "Full",

    [ValidateRange(1, 10)]
    [int]$Count = 1,

    [string]$OutputDir = "$PSScriptRoot\..\outputs\benchmarks",

    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Setup
# ============================================================================

Write-Host "DataVanger Benchmark Harness (Phase 11 Telemetry)" -ForegroundColor Cyan
Write-Host "Profile: $Profile | Runs: $Count | Output: $OutputDir" -ForegroundColor Gray

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
}

# Locate DataVanger executable
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    # Try common build paths
    $candidates = @(
        "$PSScriptRoot\..\DataVanger\bin\Release\net9.0\DataVanger.exe",
        "$PSScriptRoot\..\DataVanger\bin\Debug\net9.0\DataVanger.exe",
        (Get-Command DataVanger -ErrorAction SilentlyContinue).Source,
        "C:\Program Files\DataVanger\DataVanger.exe"
    )

    $DataVangerExe = $null
    foreach ($path in $candidates) {
        if ($path -and (Test-Path $path)) {
            $DataVangerExe = $path
            break
        }
    }

    if (-not $DataVangerExe) {
        Write-Error "DataVanger executable not found. Specify -ConfigPath or build the project first."
        exit 1
    }
} else {
    $DataVangerExe = $ConfigPath
    if (-not (Test-Path $DataVangerExe)) {
        Write-Error "DataVanger executable not found at: $DataVangerExe"
        exit 1
    }
}

Write-Host "Using: $DataVangerExe" -ForegroundColor Gray

# ============================================================================
# Benchmark Loop
# ============================================================================

$baselineFile = "$OutputDir\baseline_${profile}.json"
$results = @()

for ($i = 1; $i -le $Count; $i++) {
    $runLabel = if ($Count -eq 1) { "Single run" } else { "Run $i/$Count" }
    $cacheType = if ($i -eq 1) { "(cold cache)" } else { "(warm cache)" }

    Write-Host "`n[$runLabel $cacheType]" -ForegroundColor Cyan

    $startTime = Get-Date
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Execute scan (adjust arguments based on your DataVanger CLI signature)
    Write-Host "  Launching scan with profile=$Profile..."
    & $DataVangerExe --profile $Profile --output-telemetry | Out-Null

    $stopwatch.Stop()
    $elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    $endTime = Get-Date

    Write-Host "  Scan completed in $elapsedSeconds seconds" -ForegroundColor Green

    # Wait for telemetry JSON to be written (brief delay for I/O flush)
    Start-Sleep -Milliseconds 500

    # Locate telemetry file (DataVanger_Telemetry.json should be in same dir as executable)
    $telemetryPath = Join-Path (Split-Path $DataVangerExe) "DataVanger_Telemetry.json"

    if (Test-Path $telemetryPath) {
        $telemetryData = Get-Content $telemetryPath | ConvertFrom-Json
        $totalSeconds = $telemetryData.totalSeconds
        $filesScanned = $telemetryData.filesScanned
        $filesPerSecond = $telemetryData.filesPerSecond

        # Copy telemetry for archival
        $archivePath = "$OutputDir\telemetry_${profile}_run${i}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Copy-Item $telemetryPath $archivePath -Force

        Write-Host "  Files scanned: $filesScanned" -ForegroundColor Gray
        Write-Host "  Scan time: $([math]::Round($totalSeconds, 2))s ($([math]::Round($filesPerSecond, 1)) files/sec)" -ForegroundColor Gray
        Write-Host "  Telemetry: $archivePath" -ForegroundColor Gray

        $result = @{
            RunNumber = $i
            Profile = $Profile
            CacheType = if ($i -eq 1) { "Cold" } else { "Warm" }
            TotalSeconds = $totalSeconds
            FilesScanned = $filesScanned
            FilesPerSecond = $filesPerSecond
            TelemetryPath = $archivePath
            StartTime = $startTime
            EndTime = $endTime
        }
        $results += $result

        # Save baseline on first run
        if ($i -eq 1 -and -not (Test-Path $baselineFile)) {
            Copy-Item $archivePath $baselineFile -Force
            Write-Host "  Baseline saved: $baselineFile" -ForegroundColor Green
        }
    } else {
        Write-Warning "  Telemetry file not found at: $telemetryPath"
        Write-Warning "  Ensure DataVanger.exe is built with telemetry support enabled."
    }
}

# ============================================================================
# Comparative Analysis
# ============================================================================

if ($results.Count -gt 0 -and (Test-Path $baselineFile)) {
    Write-Host "`n[Comparative Analysis]" -ForegroundColor Cyan

    $baseline = Get-Content $baselineFile | ConvertFrom-Json
    $baselineSeconds = $baseline.totalSeconds
    $baselineFilesPerSec = $baseline.filesPerSecond

    Write-Host "Baseline (cold cache): $([math]::Round($baselineSeconds, 2))s ($([math]::Round($baselineFilesPerSec, 1)) files/sec)"

    foreach ($result in $results | Where-Object { $_.RunNumber -gt 1 }) {
        $improvement = [math]::Round(
            (($baselineSeconds - $result.TotalSeconds) / $baselineSeconds) * 100, 1)
        $fpsImprovement = [math]::Round(
            (($result.FilesPerSecond - $baselineFilesPerSec) / $baselineFilesPerSec) * 100, 1)

        Write-Host "`n$($result.CacheType) cache (Run $($result.RunNumber)):"
        Write-Host "  Time: $([math]::Round($result.TotalSeconds, 2))s"
        Write-Host "  Change vs baseline: $improvement% $(if ($improvement -gt 0) { '↑ slower' } else { '↓ faster' })"
        Write-Host "  Files/sec: $([math]::Round($result.FilesPerSecond, 1))"
        Write-Host "  FPS change: $fpsImprovement% $(if ($fpsImprovement -gt 0) { '↑ faster' } else { '↓ slower' })"
    }
}

# ============================================================================
# Summary Report
# ============================================================================

$summaryFile = "$OutputDir\benchmark_summary_${profile}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Select-Object RunNumber, CacheType, TotalSeconds, FilesScanned, FilesPerSecond |
    Export-Csv -Path $summaryFile -NoTypeInformation

Write-Host "`n[Summary]" -ForegroundColor Cyan
Write-Host "Runs completed: $($results.Count)" -ForegroundColor Green
Write-Host "Summary CSV: $summaryFile" -ForegroundColor Green
Write-Host "All telemetry archived in: $OutputDir" -ForegroundColor Green

Write-Host "`nBenchmark harness completed successfully." -ForegroundColor Green
