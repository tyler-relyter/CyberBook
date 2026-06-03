#Requires -Version 5.0
<#
.SYNOPSIS
    Generate an HTML + CSV report from a STIG assessment JSON file.
.DESCRIPTION
    Reads the JSON produced by Invoke-STIGAssessment.ps1 and renders:
      - An HTML dashboard with color-coded findings and severity summary
      - A filtered CSV for easy import into Excel / ticketing tools
.PARAMETER JsonPath
    Path to the STIG findings JSON file (required).
.PARAMETER OutputPath
    Directory to write report output. Defaults to the same folder as JsonPath.
.PARAMETER OpenReport
    Switch: open the HTML report in the default browser when done.
.EXAMPLE
    .\New-STIGReport.ps1 -JsonPath .\reports\STIG_Report_HOST_20260601.json -OpenReport
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$JsonPath,
    [string]$OutputPath = "",
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve paths ─────────────────────────────────────────────────────────────
if (-not (Test-Path $JsonPath)) { throw "JSON file not found: $JsonPath" }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Split-Path $JsonPath -Parent
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$raw      = Get-Content $JsonPath -Raw | ConvertFrom-Json
$meta     = $raw.metadata
$summary  = $raw.summary
$checks   = $raw.checks
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$basename  = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)

# ── CSV export ────────────────────────────────────────────────────────────────
$csvPath = Join-Path $OutputPath "${basename}_report.csv"
$checks | Select-Object stig_id,title,severity,status,description,check,fix,pass_criteria,evidence |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV  written: $csvPath" -ForegroundColor Green

# ── Severity color map ────────────────────────────────────────────────────────
function Get-SevColor([string]$sev) {
    switch ($sev) {
        "CAT_I"   { return "#c0392b" }
        "CAT_II"  { return "#e67e22" }
        "CAT_III" { return "#f1c40f" }
        default   { return "#95a5a6" }
    }
}
function Get-StatusColor([string]$status) {
    switch ($status) {
        "Pass"   { return "#27ae60" }
        "Fail"   { return "#e74c3c" }
        "Manual" { return "#3498db" }
        "Error"  { return "#8e44ad" }
        default  { return "#95a5a6" }
    }
}

# ── Build HTML rows ───────────────────────────────────────────────────────────
$rows = foreach ($c in $checks) {
    $sevColor    = Get-SevColor    $c.severity
    $statusColor = Get-StatusColor $c.status
    $sevLabel    = $c.severity -replace "_"," "
    @"
<tr>
  <td><span class="badge" style="background:$sevColor;">$sevLabel</span></td>
  <td><code>$($c.stig_id)</code></td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($c.title))</td>
  <td><span class="badge status" style="background:$statusColor;">$($c.status)</span></td>
  <td class="evidence">$([System.Web.HttpUtility]::HtmlEncode($c.evidence))</td>
  <td class="fix-col">$([System.Web.HttpUtility]::HtmlEncode($c.fix))</td>
</tr>
"@
}

$rowsHtml = $rows -join "`n"

# ── Compute stats for chart ────────────────────────────────────────────────────
$catIPct   = if ($summary.total_checks -gt 0) { [math]::Round((($checks | Where-Object { $_.severity -eq "CAT_I"   -and $_.status -eq "Fail" }).Count / $summary.total_checks) * 100, 1) } else { 0 }
$catIIPct  = if ($summary.total_checks -gt 0) { [math]::Round((($checks | Where-Object { $_.severity -eq "CAT_II"  -and $_.status -eq "Fail" }).Count / $summary.total_checks) * 100, 1) } else { 0 }
$catIIIPct = if ($summary.total_checks -gt 0) { [math]::Round((($checks | Where-Object { $_.severity -eq "CAT_III" -and $_.status -eq "Fail" }).Count / $summary.total_checks) * 100, 1) } else { 0 }

# ── HTML template ─────────────────────────────────────────────────────────────
Add-Type -AssemblyName System.Web 2>$null

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STIG Assessment Report - $($meta.system)</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
  header { background: linear-gradient(135deg, #161b22 0%, #1f2937 100%);
           border-bottom: 2px solid #30363d; padding: 24px 40px; }
  header h1 { font-size: 1.6rem; color: #58a6ff; }
  header p  { color: #8b949e; font-size: 0.9rem; margin-top: 4px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 40px; }

  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
           gap: 16px; margin-bottom: 32px; }
  .card  { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           padding: 20px; text-align: center; }
  .card .num  { font-size: 2.2rem; font-weight: 700; }
  .card .label{ font-size: 0.8rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .green  { color: #3fb950; }
  .red    { color: #f85149; }
  .orange { color: #e3b341; }
  .blue   { color: #58a6ff; }
  .purple { color: #bc8cff; }

  /* Table */
  .table-wrap { overflow-x: auto; }
  table  { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  thead th { background: #161b22; color: #8b949e; font-weight: 600;
             padding: 10px 12px; text-align: left; border-bottom: 2px solid #30363d;
             position: sticky; top: 0; }
  tbody tr { border-bottom: 1px solid #21262d; transition: background .15s; }
  tbody tr:hover { background: #1c2128; }
  td { padding: 10px 12px; vertical-align: top; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 0.75rem; font-weight: 600; color: #fff; white-space: nowrap; }
  .status { font-size: 0.78rem; }
  code   { background: #21262d; padding: 2px 6px; border-radius: 4px;
           font-family: monospace; font-size: 0.82rem; color: #58a6ff; }
  .evidence { color: #8b949e; font-size: 0.8rem; max-width: 280px; }
  .fix-col  { color: #7c8c8c; font-size: 0.78rem; max-width: 240px; }

  /* Filters */
  .filters { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .filter-btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9;
                padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
  .filter-btn:hover, .filter-btn.active { background: #58a6ff; color: #0d1117; border-color: #58a6ff; }

  /* Section title */
  h2 { font-size: 1.1rem; color: #c9d1d9; margin-bottom: 16px; padding-bottom: 8px;
       border-bottom: 1px solid #30363d; }
  .section { margin-bottom: 40px; }
  footer { text-align: center; color: #484f58; font-size: 0.8rem; padding: 24px; }
</style>
</head>
<body>

<header>
  <h1>&#x1F6E1; STIG Compliance Assessment Report</h1>
  <p>Host: <strong>$($meta.system)</strong> &nbsp;|&nbsp;
     Platform: $($meta.platform) &nbsp;|&nbsp;
     STIG: $($meta.stig_version) &nbsp;|&nbsp;
     OS: $($meta.os_caption) $($meta.os_version) &nbsp;|&nbsp;
     Generated: $($meta.generated_at)</p>
</header>

<div class="container">

  <!-- Summary cards -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="cards">
      <div class="card">
        <div class="num blue">$($summary.total_checks)</div>
        <div class="label">Total Checks</div>
      </div>
      <div class="card">
        <div class="num green">$($summary.passed)</div>
        <div class="label">Passed</div>
      </div>
      <div class="card">
        <div class="num red">$($summary.failed)</div>
        <div class="label">Failed</div>
      </div>
      <div class="card">
        <div class="num orange">$($summary.manual_required)</div>
        <div class="label">Manual Review</div>
      </div>
      <div class="card">
        <div class="num red">$($summary.cat_I_failures)</div>
        <div class="label">CAT I Failures</div>
      </div>
      <div class="card">
        <div class="num orange">$($summary.cat_II_failures)</div>
        <div class="label">CAT II Failures</div>
      </div>
      <div class="card">
        <div class="num" style="color:#f1c40f;">$($summary.cat_III_failures)</div>
        <div class="label">CAT III Failures</div>
      </div>
      <div class="card">
        <div class="num $(if ($summary.compliance_pct -ge 80) { 'green' } elseif ($summary.compliance_pct -ge 60) { 'orange' } else { 'red' })">$($summary.compliance_pct)%</div>
        <div class="label">Compliance</div>
      </div>
    </div>
  </div>

  <!-- Findings table -->
  <div class="section">
    <h2>Detailed Findings</h2>
    <div class="filters">
      <button class="filter-btn active" onclick="filterTable('ALL')">All</button>
      <button class="filter-btn" onclick="filterTable('Fail')" style="color:#f85149;">Failures Only</button>
      <button class="filter-btn" onclick="filterTable('CAT_I')" style="color:#f85149;">CAT I</button>
      <button class="filter-btn" onclick="filterTable('CAT_II')" style="color:#e3b341;">CAT II</button>
      <button class="filter-btn" onclick="filterTable('CAT_III')" style="color:#f1c40f;">CAT III</button>
      <button class="filter-btn" onclick="filterTable('Pass')" style="color:#3fb950;">Passed</button>
    </div>
    <div class="table-wrap">
      <table id="findingsTable">
        <thead>
          <tr>
            <th>Severity</th>
            <th>STIG ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Evidence</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody id="tableBody">
          $rowsHtml
        </tbody>
      </table>
    </div>
  </div>

</div>

<footer>
  Generated by CyberBook STIG Assessment Tool &mdash; $($meta.stig_version) &mdash; $($meta.generated_at)
</footer>

<script>
function filterTable(filter) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  const rows = document.querySelectorAll('#tableBody tr');
  rows.forEach(row => {
    const text = row.innerText;
    if (filter === 'ALL') {
      row.style.display = '';
    } else if (filter === 'Fail') {
      row.style.display = text.includes('Fail') ? '' : 'none';
    } else if (filter === 'Pass') {
      row.style.display = text.includes('Pass') && !text.includes('Fail') ? '' : 'none';
    } else {
      row.style.display = text.includes(filter.replace('_',' ')) ? '' : 'none';
    }
  });
}
</script>

</body>
</html>
"@

$htmlPath = Join-Path $OutputPath "${basename}_report.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "[+] HTML written: $htmlPath" -ForegroundColor Green

if ($OpenReport) {
    Start-Process $htmlPath
}

Write-Host ""
Write-Host "Report generation complete." -ForegroundColor Cyan
