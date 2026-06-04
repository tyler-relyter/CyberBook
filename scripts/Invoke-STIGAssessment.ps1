#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 STIG Compliance Assessment Tool
.DESCRIPTION
    Automated STIG compliance scanner for Windows 11 based on DISA STIG WN11 V2R8.
    Evaluates system configuration against all 223 benchmark controls and generates
    JSON and CSV findings reports with CAT I/II/III severity ratings.
.PARAMETER OutputPath
    Directory to write report files. Defaults to .\reports
.PARAMETER Format
    Output format: JSON, CSV, or Both (default: Both)
.PARAMETER ModulesPath
    Path to STIG check module scripts. Defaults to .\modules
.EXAMPLE
    .\Invoke-STIGAssessment.ps1 -OutputPath C:\Reports -Format Both
#>

[CmdletBinding()]
param(
    [string]$OutputPath   = ".\reports",
    [ValidateSet("JSON","CSV","Both")]
    [string]$Format       = "Both",
    [string]$ModulesPath  = ".\modules"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Banner
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   DISA STIG Windows 11 Automated Compliance Assessment     " -ForegroundColor Cyan
Write-Host "   Version: 2.1  |  WN11 V2R8 + Firewall V2R3              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Prerequisites
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME
$osInfo    = Get-CimInstance Win32_OperatingSystem
$findings  = [System.Collections.Generic.List[PSObject]]::new()

# Metadata
$metadata = [ordered]@{
    system        = $hostname
    platform      = "Windows 11"
    stig_version  = "WN11 V2R8"
    os_version    = $osInfo.Version
    os_caption    = $osInfo.Caption
    generated_at  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    assessed_by   = $env:USERNAME
}

# Modules to load
$modules = @(
    "Check-General.ps1",
    "Check-AccountPolicy.ps1",
    "Check-AuditPolicy.ps1",
    "Check-CCSettings.ps1",
    "Check-SecurityOptions.ps1",
    "Check-UserRights.ps1",
    "Check-Miscellaneous.ps1",
    "Check-Firewall.ps1"
)

Write-Host "[*] Loading STIG check modules..." -ForegroundColor Yellow

foreach ($mod in $modules) {
    $modPath = Join-Path $ModulesPath $mod
    if (Test-Path $modPath) {
        Write-Host "    -> Loading: $mod" -ForegroundColor Gray
        try {
            $modFindings = & $modPath
            if ($null -ne $modFindings) {
                foreach ($f in @($modFindings)) {
                    $findings.Add($f)
                }
            }
        } catch {
            Write-Warning "    [!] Module error in ${mod}: $_"
        }
    } else {
        Write-Warning "    [!] Module not found: $modPath"
    }
}

# Tally Results
# Wrap Where-Object in @() to force array under Set-StrictMode -Version Latest.
# Without @(), a single match returns PSObject which has no .Count property.
$total       = $findings.Count
$passed      = @($findings | Where-Object { $_.status -eq "Pass"   }).Count
$failed      = @($findings | Where-Object { $_.status -eq "Fail"   }).Count
$manual      = @($findings | Where-Object { $_.status -eq "Manual" }).Count
$errors      = @($findings | Where-Object { $_.status -eq "Error"  }).Count
$catI_fail   = @($findings | Where-Object { $_.status -eq "Fail" -and $_.severity -eq "CAT_I"   }).Count
$catII_fail  = @($findings | Where-Object { $_.status -eq "Fail" -and $_.severity -eq "CAT_II"  }).Count
$catIII_fail = @($findings | Where-Object { $_.status -eq "Fail" -and $_.severity -eq "CAT_III" }).Count

$summary = [ordered]@{
    total_checks     = $total
    passed           = $passed
    failed           = $failed
    manual_required  = $manual
    errors           = $errors
    cat_I_failures   = $catI_fail
    cat_II_failures  = $catII_fail
    cat_III_failures = $catIII_fail
    compliance_pct   = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }
}

# Resolve script directory reliably — $PSScriptRoot is empty when called via
# batch file with a relative path, so fall back to MyInvocation.
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } `
             else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# Always define $jsonPath so the HTML block can reference it safely
$jsonPath = $null

# Output: JSON
if ($Format -in "JSON","Both") {
    $jsonOutput = [ordered]@{
        metadata = $metadata
        summary  = $summary
        checks   = $findings
    }
    $jsonPath = Join-Path $OutputPath "STIG_Report_${hostname}_${timestamp}.json"
    $jsonOutput | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host ""
    Write-Host "[+] JSON report written: $jsonPath" -ForegroundColor Green
}

# Output: CSV
if ($Format -in "CSV","Both") {
    $csvPath = Join-Path $OutputPath "STIG_Report_${hostname}_${timestamp}.csv"
    $findings | Select-Object stig_id,title,severity,description,check,fix,pass_criteria,status,evidence |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV  report written: $csvPath" -ForegroundColor Green
}

# Output: HTML (auto-generated from the JSON written above)
if ($null -ne $jsonPath -and (Test-Path $jsonPath)) {
    $reportScript = Join-Path $scriptDir "New-STIGReport.ps1"
    if (Test-Path $reportScript) {
        Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow
        try {
            & $reportScript -JsonPath $jsonPath -OutputPath $OutputPath
        } catch {
            Write-Warning "[!] HTML report generation failed: $_"
        }
    } else {
        Write-Warning "[!] New-STIGReport.ps1 not found at: $reportScript"
    }
}

# Console Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ASSESSMENT SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Host         : $hostname"
Write-Host "  Total Checks : $total"
Write-Host ("  Passed       : {0}" -f $passed) -ForegroundColor Green
Write-Host ("  Failed       : {0}  (CAT I:{1}  CAT II:{2}  CAT III:{3})" -f $failed,$catI_fail,$catII_fail,$catIII_fail) -ForegroundColor Red
Write-Host ("  Manual Review: {0}" -f $manual) -ForegroundColor Yellow
Write-Host ("  Errors       : {0}" -f $errors)
Write-Host ("  Compliance   : {0}%" -f $summary.compliance_pct)
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
