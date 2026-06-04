#Requires -Version 5.0
<#
.SYNOPSIS
    Generate a self-contained HTML report from a STIG assessment JSON file.
.DESCRIPTION
    Reads JSON produced by Invoke-STIGAssessment.ps1 and generates:
      - A fully self-contained HTML dashboard (no CDN, no external deps)
      - Color-coded findings table with client-side filtering and search
      - Executive summary cards with compliance percentage
      - Exportable to CSV directly from the browser
    No System.Web dependency -- HTML encoding done in pure PowerShell.
.PARAMETER JsonPath
    Path to the STIG findings JSON file (required).
.PARAMETER OutputPath
    Directory for the HTML output. Defaults to the JSON file's folder.
.PARAMETER OpenReport
    Switch: open the HTML in the default browser after generation.
.EXAMPLE
    .\New-STIGReport.ps1 -JsonPath .\reports\STIG_Report_HOST_20260603.json -OpenReport
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

# ── Pure-PS HTML encoder (no System.Web required) ─────────────────────────────
function ConvertTo-HtmlEncoded([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return '' }
    $s = $s -replace '&',  '&amp;'
    $s = $s -replace '<',  '&lt;'
    $s = $s -replace '>',  '&gt;'
    $s = $s -replace '"',  '&quot;'
    $s = $s -replace "'",  '&#39;'
    return $s
}

# ── Resolve paths ──────────────────────────────────────────────────────────────
if (-not (Test-Path $JsonPath)) { throw "JSON not found: $JsonPath" }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Split-Path $JsonPath -Parent
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "[*] Loading JSON: $JsonPath" -ForegroundColor Cyan
$raw     = Get-Content $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
$meta    = $raw.metadata
$summary = $raw.summary
$checks  = @($raw.checks)
$base    = [System.IO.Path]::GetFileNameWithoutExtension($JsonPath)
$htmlPath = Join-Path $OutputPath "${base}_report.html"

Write-Host "[*] Building report for $($meta.system) -- $($checks.Count) findings..." -ForegroundColor Cyan

# ── Severity helpers ───────────────────────────────────────────────────────────
function Get-SevBadge([string]$sev) {
    switch ($sev) {
        'CAT_I'   { return '<span class="badge sev1">CAT I</span>' }
        'CAT_II'  { return '<span class="badge sev2">CAT II</span>' }
        'CAT_III' { return '<span class="badge sev3">CAT III</span>' }
        default   { return '<span class="badge sevx">?</span>' }
    }
}

function Get-StatusBadge([string]$st) {
    switch ($st) {
        'Pass'   { return '<span class="badge pass">PASS</span>' }
        'Fail'   { return '<span class="badge fail">FAIL</span>' }
        'Manual' { return '<span class="badge manual">MANUAL</span>' }
        'Error'  { return '<span class="badge err">ERROR</span>' }
        default  { return '<span class="badge sevx">?</span>' }
    }
}

# ── Build table rows (JavaScript data array) ──────────────────────────────────
$jsRows = [System.Text.StringBuilder]::new()
foreach ($c in $checks) {
    $sid   = ConvertTo-HtmlEncoded $c.stig_id
    $title = ConvertTo-HtmlEncoded $c.title
    $sev   = ConvertTo-HtmlEncoded $c.severity
    $st    = ConvertTo-HtmlEncoded $c.status
    $ev    = ConvertTo-HtmlEncoded $c.evidence
    $fix   = ConvertTo-HtmlEncoded $c.fix
    $desc  = ConvertTo-HtmlEncoded $c.description
    $check = ConvertTo-HtmlEncoded $c.check
    $pc    = ConvertTo-HtmlEncoded $c.pass_criteria

    # Escape for JS string literal
    $titleJs = $title -replace '\\', '\\\\' -replace "'", "\'"
    $evJs    = $ev    -replace '\\', '\\\\' -replace "'", "\'"
    $fixJs   = $fix   -replace '\\', '\\\\' -replace "'", "\'"
    $descJs  = $desc  -replace '\\', '\\\\' -replace "'", "\'"
    $checkJs = $check -replace '\\', '\\\\' -replace "'", "\'"
    $pcJs    = $pc    -replace '\\', '\\\\' -replace "'", "\'"

    [void]$jsRows.Append("  ['$sid','$titleJs','$sev','$st','$evJs','$fixJs','$descJs','$checkJs','$pcJs'],`n")
}

# ── Compliance gauge arc ───────────────────────────────────────────────────────
$pct      = [double]$summary.compliance_pct
$arcColor = if ($pct -ge 80) { '#3fb950' } elseif ($pct -ge 60) { '#e3b341' } else { '#f85149' }
$circumference = 2 * 3.14159 * 54
$dashOffset    = $circumference * (1 - ($pct / 100))

# ── Full HTML ──────────────────────────────────────────────────────────────────
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>STIG Report - $($meta.system)</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:14px}
a{color:#58a6ff}

/* Header */
header{background:linear-gradient(135deg,#161b22,#1c2333);border-bottom:2px solid #30363d;padding:20px 32px;display:flex;align-items:center;gap:20px}
header .logo{font-size:28px}
header h1{font-size:1.4rem;color:#58a6ff;margin-bottom:3px}
header p{color:#8b949e;font-size:.82rem}
header .stamp{margin-left:auto;text-align:right;font-size:.78rem;color:#6e7681;line-height:1.6}

/* Layout */
.wrap{max-width:1440px;margin:0 auto;padding:24px 32px}
h2{font-size:1rem;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin:0 0 16px}

/* Cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:32px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 12px;text-align:center}
.card .n{font-size:2rem;font-weight:700;line-height:1}
.card .l{font-size:.72rem;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}
.green{color:#3fb950}.red{color:#f85149}.orange{color:#e3b341}.yellow{color:#d29922}.blue{color:#58a6ff}.purple{color:#bc8cff}.gray{color:#8b949e}

/* Gauge */
.gauge-wrap{display:flex;align-items:center;gap:32px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px 28px;margin-bottom:32px}
.gauge svg{flex-shrink:0}
.gauge-stats{display:grid;grid-template-columns:1fr 1fr;gap:10px 32px}
.gauge-stat .val{font-size:1.4rem;font-weight:700}
.gauge-stat .lbl{font-size:.75rem;color:#8b949e;text-transform:uppercase}

/* Toolbar */
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center}
.filter-btn{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:.82rem;transition:.15s}
.filter-btn:hover{border-color:#58a6ff;color:#58a6ff}
.filter-btn.active{background:#58a6ff;color:#0d1117;border-color:#58a6ff}
.search-box{margin-left:auto;background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:5px 12px;border-radius:6px;font-size:.82rem;width:220px;outline:none}
.search-box:focus{border-color:#58a6ff}
.export-btn{background:#238636;border:1px solid #2ea043;color:#fff;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:.82rem}
.export-btn:hover{background:#2ea043}

/* Table */
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid #30363d}
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead th{background:#161b22;color:#8b949e;font-weight:600;padding:9px 12px;text-align:left;border-bottom:2px solid #30363d;white-space:nowrap;position:sticky;top:0;z-index:2}
thead th.sort{cursor:pointer;user-select:none}
thead th.sort:hover{color:#c9d1d9}
tbody tr{border-bottom:1px solid #21262d;transition:background .12s;cursor:pointer}
tbody tr:hover{background:#1c2128}
tbody tr.expanded{background:#161b22}
td{padding:9px 12px;vertical-align:top}
td.ev{color:#8b949e;max-width:260px;word-break:break-word}
td.fix-c{color:#6e7681;max-width:240px;word-break:break-word}

/* Detail row */
.detail-row{display:none;background:#0d1117}
.detail-row.open{display:table-row}
.detail-inner{padding:14px 16px;display:grid;grid-template-columns:1fr 1fr;gap:14px 24px}
.detail-inner .dl{display:flex;flex-direction:column;gap:4px}
.detail-inner .dt{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.detail-inner .dd{font-size:.82rem;color:#c9d1d9;word-break:break-word}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700;color:#fff;white-space:nowrap}
.sev1{background:#b91c1c}.sev2{background:#c2610c}.sev3{background:#92400e}.sevx{background:#374151}
.pass{background:#166534}.fail{background:#b91c1c}.manual{background:#1d4ed8}.err{background:#6b21a8}

/* Count badge */
.cnt{display:inline-block;background:#30363d;border-radius:8px;padding:1px 6px;font-size:.72rem;margin-left:4px;color:#8b949e}

footer{text-align:center;color:#484f58;font-size:.75rem;padding:24px;border-top:1px solid #21262d;margin-top:40px}
</style>
</head>
<body>

<header>
  <div class="logo">&#x1F6E1;</div>
  <div>
    <h1>STIG Compliance Assessment Report</h1>
    <p>Host: <strong style="color:#c9d1d9">$(ConvertTo-HtmlEncoded $meta.system)</strong>
       &nbsp;&middot;&nbsp; $($meta.platform)
       &nbsp;&middot;&nbsp; STIG: $($meta.stig_version)
       &nbsp;&middot;&nbsp; OS: $(ConvertTo-HtmlEncoded $meta.os_caption)</p>
  </div>
  <div class="stamp">
    Generated: $($meta.generated_at)<br>
    Assessed by: $(ConvertTo-HtmlEncoded $meta.assessed_by)<br>
    Total controls: <strong style="color:#c9d1d9">$($summary.total_checks)</strong>
  </div>
</header>

<div class="wrap">

<!-- Gauge + key stats -->
<div class="gauge-wrap">
  <svg class="gauge" width="140" height="140" viewBox="0 0 120 120">
    <circle cx="60" cy="60" r="54" fill="none" stroke="#21262d" stroke-width="10"/>
    <circle cx="60" cy="60" r="54" fill="none" stroke="$arcColor" stroke-width="10"
            stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset"
            stroke-linecap="round" transform="rotate(-90 60 60)"/>
    <text x="60" y="55" text-anchor="middle" font-size="22" font-weight="700" fill="$arcColor">$($pct)%</text>
    <text x="60" y="72" text-anchor="middle" font-size="9" fill="#8b949e">COMPLIANT</text>
  </svg>
  <div class="gauge-stats">
    <div class="gauge-stat"><div class="val green">$($summary.passed)</div><div class="lbl">Passed</div></div>
    <div class="gauge-stat"><div class="val red">$($summary.failed)</div><div class="lbl">Failed</div></div>
    <div class="gauge-stat"><div class="val red">$($summary.cat_I_failures)</div><div class="lbl">CAT I Failures</div></div>
    <div class="gauge-stat"><div class="val orange">$($summary.cat_II_failures)</div><div class="lbl">CAT II Failures</div></div>
    <div class="gauge-stat"><div class="val yellow">$($summary.cat_III_failures)</div><div class="lbl">CAT III Failures</div></div>
    <div class="gauge-stat"><div class="val blue">$($summary.manual_required)</div><div class="lbl">Manual Review</div></div>
    <div class="gauge-stat"><div class="val purple">$($summary.errors)</div><div class="lbl">Check Errors</div></div>
    <div class="gauge-stat"><div class="val gray">$($summary.total_checks)</div><div class="lbl">Total Checks</div></div>
  </div>
</div>

<!-- Findings table -->
<h2>Detailed Findings</h2>
<div class="toolbar">
  <button class="filter-btn active" onclick="applyFilter('ALL',this)">All <span class="cnt" id="cnt-ALL">$($summary.total_checks)</span></button>
  <button class="filter-btn" onclick="applyFilter('Fail',this)">Failures <span class="cnt" id="cnt-Fail">$($summary.failed)</span></button>
  <button class="filter-btn" onclick="applyFilter('CAT_I',this)">CAT I</button>
  <button class="filter-btn" onclick="applyFilter('CAT_II',this)">CAT II</button>
  <button class="filter-btn" onclick="applyFilter('CAT_III',this)">CAT III</button>
  <button class="filter-btn" onclick="applyFilter('Pass',this)">Passed <span class="cnt" id="cnt-Pass">$($summary.passed)</span></button>
  <button class="filter-btn" onclick="applyFilter('Manual',this)">Manual <span class="cnt" id="cnt-Manual">$($summary.manual_required)</span></button>
  <input class="search-box" id="search" type="text" placeholder="Search STIG ID, title, evidence..." oninput="applySearch()">
  <button class="export-btn" onclick="exportCSV()">&#x2B07; Export CSV</button>
</div>

<div class="tbl-wrap">
<table id="tbl">
  <thead>
    <tr>
      <th class="sort" onclick="sortTable(0)">Severity &#x2195;</th>
      <th class="sort" onclick="sortTable(1)">STIG ID &#x2195;</th>
      <th>Title</th>
      <th class="sort" onclick="sortTable(3)">Status &#x2195;</th>
      <th>Evidence</th>
      <th>Remediation</th>
    </tr>
  </thead>
  <tbody id="tbody"></tbody>
</table>
</div>

<p id="vis-count" style="text-align:right;color:#6e7681;font-size:.78rem;margin-top:8px"></p>

</div><!-- .wrap -->

<footer>
  CyberBook STIG Assessment Tool &mdash; $($meta.stig_version) &mdash; $($meta.generated_at)
</footer>

<script>
// ── Raw data ──────────────────────────────────────────────────────────────────
// Columns: [stig_id, title, severity, status, evidence, fix, description, check, pass_criteria]
const DATA = [
$($jsRows.ToString())];

// ── Severity / status sort order ─────────────────────────────────────────────
const SEV_ORDER  = {CAT_I:0,CAT_II:1,CAT_III:2};
const STAT_ORDER = {Fail:0,Error:1,Manual:2,Pass:3};

// ── Badge renderers ───────────────────────────────────────────────────────────
function sevBadge(s) {
  const cls = {CAT_I:'sev1',CAT_II:'sev2',CAT_III:'sev3'}[s]||'sevx';
  const lbl = s.replace('_',' ');
  return '<span class="badge ' + cls + '">' + lbl + '</span>';
}
function statBadge(s) {
  const cls = {Pass:'pass',Fail:'fail',Manual:'manual',Error:'err'}[s]||'sevx';
  return '<span class="badge ' + cls + '">' + s.toUpperCase() + '</span>';
}

// ── State ─────────────────────────────────────────────────────────────────────
let activeFilter = 'ALL';
let searchTerm   = '';
let sortCol      = 0;   // default: severity
let sortAsc      = true;
let visibleRows  = [];

// ── Filter + render ───────────────────────────────────────────────────────────
function render() {
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';

  // Filter
  let rows = DATA.filter(r => {
    if (activeFilter !== 'ALL') {
      if (activeFilter === 'Fail'   && r[3] !== 'Fail')    return false;
      if (activeFilter === 'Pass'   && r[3] !== 'Pass')    return false;
      if (activeFilter === 'Manual' && r[3] !== 'Manual')  return false;
      if (activeFilter === 'CAT_I'  && r[2] !== 'CAT_I')  return false;
      if (activeFilter === 'CAT_II' && r[2] !== 'CAT_II') return false;
      if (activeFilter === 'CAT_III'&& r[2] !== 'CAT_III')return false;
    }
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return r[0].toLowerCase().includes(q) ||
             r[1].toLowerCase().includes(q) ||
             r[4].toLowerCase().includes(q) ||
             r[6].toLowerCase().includes(q);
    }
    return true;
  });

  // Sort
  rows.sort((a,b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (sortCol === 0) { va = SEV_ORDER[va]??9;  vb = SEV_ORDER[vb]??9; }
    if (sortCol === 3) { va = STAT_ORDER[va]??9; vb = STAT_ORDER[vb]??9; }
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ?  1 : -1;
    return 0;
  });

  visibleRows = rows;

  rows.forEach((r, i) => {
    const id = 'row-' + i;
    const mainRow = document.createElement('tr');
    mainRow.innerHTML =
      '<td>' + sevBadge(r[2]) + '</td>' +
      '<td><code style="background:#21262d;padding:2px 6px;border-radius:4px;font-size:.78rem;color:#58a6ff">' + r[0] + '</code></td>' +
      '<td style="max-width:320px">' + r[1] + '</td>' +
      '<td>' + statBadge(r[3]) + '</td>' +
      '<td class="ev">' + r[4] + '</td>' +
      '<td class="fix-c">' + r[5] + '</td>';
    mainRow.onclick = function() { toggleDetail(id); };

    const detRow = document.createElement('tr');
    detRow.className = 'detail-row';
    detRow.id = id;
    detRow.innerHTML =
      '<td colspan="6"><div class="detail-inner">' +
      '<div class="dl"><div class="dt">Description</div><div class="dd">'    + (r[6]||'&mdash;') + '</div></div>' +
      '<div class="dl"><div class="dt">Check Command</div><div class="dd"><code style="font-size:.78rem">' + (r[7]||'&mdash;') + '</code></div></div>' +
      '<div class="dl"><div class="dt">Pass Criteria</div><div class="dd">'  + (r[8]||'&mdash;') + '</div></div>' +
      '<div class="dl"><div class="dt">Full Remediation</div><div class="dd">' + (r[5]||'&mdash;') + '</div></div>' +
      '</div></td>';

    tbody.appendChild(mainRow);
    tbody.appendChild(detRow);
  });

  document.getElementById('vis-count').textContent =
    rows.length + ' of ' + DATA.length + ' controls shown';
}

function toggleDetail(id) {
  const row = document.getElementById(id);
  row.classList.toggle('open');
}

function applyFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  render();
}

function applySearch() {
  searchTerm = document.getElementById('search').value.trim();
  render();
}

function sortTable(col) {
  if (sortCol === col) { sortAsc = !sortAsc; }
  else { sortCol = col; sortAsc = true; }
  render();
}

// ── CSV Export ────────────────────────────────────────────────────────────────
function exportCSV() {
  const headers = ['stig_id','title','severity','status','evidence','fix','description','check','pass_criteria'];
  const rows = [headers.join(',')];
  visibleRows.forEach(r => {
    rows.push(r.map(v => '"' + String(v).replace(/"/g,'""') + '"').join(','));
  });
  const blob = new Blob([rows.join('\r\n')], {type:'text/csv'});
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'STIG_findings_export.csv';
  a.click();
}

// ── Init ──────────────────────────────────────────────────────────────────────
render();
</script>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "[+] HTML report: $htmlPath" -ForegroundColor Green

if ($OpenReport) {
    Start-Process $htmlPath
}
