# CyberBook — Windows 11 STIG Automated Assessment Tool

Automated DISA STIG compliance scanner for Windows 11. Runs PowerShell-based checks against the **WN11 V2R8** benchmark, maps every finding to a STIG control ID, assigns a CAT I/II/III severity rating, and produces JSON, CSV, and HTML reports.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Batch launcher (recommended)](#batch-launcher-recommended)
  - [PowerShell directly](#powershell-directly)
  - [Generating the HTML report](#generating-the-html-report)
- [Output Files](#output-files)
- [Check Modules Reference](#check-modules-reference)
- [Severity Guide](#severity-guide)
- [Adding New Checks](#adding-new-checks)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

CyberBook translates **all 243 controls** from two DISA STIGs into deterministic, scriptable checks that run without any third-party tooling:
- **WN11 V2R8** — Windows 11 STIG (223 controls, benchmark date: 01 Apr 2026)
- **Firewall V2R3** — Windows Defender Firewall STIG (20 controls) Each check:

1. Queries the live system (registry, `net accounts`, `auditpol`, `secedit`, WMI/CIM, BitLocker/TPM cmdlets)
2. Compares the result against the STIG pass criterion
3. Records a structured finding: `Pass`, `Fail`, `Manual`, or `Error`
4. Emits machine-readable output (JSON + CSV) and an optional HTML dashboard

This is intentionally a **PowerShell-native** tool — no SCAP, SCC, or Nessus required, though it can complement those tools.

---

## Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Windows | Windows 11 | Script targets WN11 V2R8 STIG; may partially work on Win 10 |
| PowerShell | 5.1 | Ships with Windows 11 by default |
| Privileges | Administrator | Required for `secedit`, `auditpol`, BitLocker, and LSA registry reads |
| Execution Policy | Any (bypassed at runtime) | The batch launcher passes `-ExecutionPolicy Bypass` |

---

## Project Structure

```
CyberBook/
├── README.md
│
└── scripts/
    ├── Invoke-STIGAssessment.ps1     # Main orchestrator — loads modules, writes reports
    ├── New-STIGReport.ps1            # Report generator — JSON → HTML + CSV dashboard
    ├── Run-STIGAssessment.bat        # Batch launcher with auto-elevation and fallback
    │
    ├── reports/                      # Created automatically on first run
    │   ├── STIG_Report_<HOST>_<TS>.json
    │   ├── STIG_Report_<HOST>_<TS>.csv
    │   └── STIG_Report_<HOST>_<TS>_report.html       #TODO
    │
    └── modules/
        ├── Check-General.ps1         # WN11-00-* : BitLocker, NTFS, optional features, SMBv1
        ├── Check-AccountPolicy.ps1   # WN11-AC-* : Password & lockout policy (9 controls)
        ├── Check-AuditPolicy.ps1     # WN11-AU-* : Audit subcategories + event log size (53 controls)
        ├── Check-CCSettings.ps1      # WN11-CC-*, WN11-EP-*, WN11-PK-* : Registry/GPO settings (76 controls)
        ├── Check-SecurityOptions.ps1 # WN11-SO-* : LSA, UAC, SMB signing, NTLM (40 controls)
        ├── Check-UserRights.ps1      # WN11-UR-* : User Rights Assignment (29 controls)
        ├── Check-Miscellaneous.ps1   # WN11-UC-* : User configuration settings
        └── Check-Firewall.ps1        # WNFWA-* : Windows Defender Firewall V2R3 (20 controls)
```

---

## Quick Start

1. Right-click `scripts\Run-STIGAssessment.bat`
2. Select **Run as administrator**
3. Wait for the scan to finish (~30–60 seconds)
4. Reports open automatically in `scripts\reports\`

---

## Usage

### Batch launcher (recommended)

```bat
Run-STIGAssessment.bat
```

The batch file handles:
- UAC elevation (re-launches itself as admin if needed)
- PowerShell version check (requires 5.1+)
- Informational check for optional SCC/SCAP tools
- Fallback verbose re-run on failure (prompts Y/N)
- Opens the `reports\` folder in Explorer on success

### PowerShell directly

```powershell
# Basic run — writes JSON + CSV to .\reports\
.\Invoke-STIGAssessment.ps1

# Custom output path, JSON only
.\Invoke-STIGAssessment.ps1 -OutputPath C:\AuditReports -Format JSON

# Point at a different modules directory
.\Invoke-STIGAssessment.ps1 -ModulesPath D:\CustomModules -OutputPath C:\Reports
```

**Parameters**

| Parameter | Default | Description |
|---|---|---|
| `-OutputPath` | `.\reports` | Directory for report output |
| `-Format` | `Both` | `JSON`, `CSV`, or `Both` |
| `-ModulesPath` | `.\modules` | Directory containing `Check-*.ps1` modules |

### Generating the HTML report

The HTML dashboard is generated from the JSON file produced by `Invoke-STIGAssessment.ps1`:

```powershell
# Generate HTML + CSV and open in browser
.\New-STIGReport.ps1 -JsonPath .\reports\STIG_Report_MYHOST_20260601_120000.json -OpenReport

# Generate without opening browser
.\New-STIGReport.ps1 -JsonPath .\reports\STIG_Report_MYHOST_20260601_120000.json
```

**Parameters**

| Parameter | Required | Description |
|---|---|---|
| `-JsonPath` | Yes | Path to the findings JSON file |
| `-OutputPath` | No | Output directory (defaults to JSON file's folder) |
| `-OpenReport` | No | Switch — opens HTML in default browser when done |

---

## Output Files

### JSON (`STIG_Report_<HOST>_<TS>.json`)

Full machine-readable findings including metadata, summary statistics, and per-check evidence. Schema:

```json
{
  "metadata": {
    "system": "HOSTNAME",
    "platform": "Windows 11",
    "stig_version": "WN11 V1R4",
    "os_version": "10.0.22621",
    "os_caption": "Microsoft Windows 11 Pro",
    "generated_at": "2026-06-01T12:00:00Z",
    "assessed_by": "username"
  },
  "summary": {
    "total_checks": 30,
    "passed": 22,
    "failed": 6,
    "manual_required": 1,
    "errors": 1,
    "cat_I_failures": 2,
    "cat_II_failures": 3,
    "cat_III_failures": 1,
    "compliance_pct": 73.3
  },
  "checks": [
    {
      "stig_id": "WN11-AC-000030",
      "title": "Minimum password length must be 14 characters or more",
      "severity": "CAT_II",
      "description": "...",
      "check": "net accounts | find 'Minimum password length'",
      "fix": "net accounts /minpwlen:14",
      "pass_criteria": "Value >= 14",
      "status": "Fail",
      "evidence": "Minimum password length: 8"
    }
  ]
}
```

### CSV (`STIG_Report_<HOST>_<TS>.csv`)

Flat columnar format for import into Excel, Splunk, or a ticketing system. Columns:

```
stig_id, title, severity, description, check, fix, pass_criteria, status, evidence
```

### HTML Dashboard (`*_report.html`)

Interactive, dark-themed dashboard with:
- Summary cards (total, passed, failed, CAT I/II/III breakdown, compliance %)
- Color-coded findings table (red = Fail, green = Pass, yellow = CAT III, etc.)
- Client-side filter buttons: All / Failures Only / CAT I / CAT II / CAT III / Passed
- No server required — single self-contained file, opens in any browser

---

## Check Modules Reference

Each module in `scripts/modules/` is auto-generated from the official DISA SCAP benchmark XML (`U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml`) and returns a `List[PSObject]` of findings. The orchestrator calls all 7 modules and aggregates results.

**Total coverage: 223 controls — 22 CAT I, 188 CAT II, 13 CAT III**

### Check-General.ps1 — WN11-00-*

BitLocker, OS drive encryption, NTFS volumes, optional feature removal (IIS, Telnet, TFTP, PS 2.0), SMBv1, SEHOP, Secondary Logon service.

| STIG ID | Title | CAT |
|---|---|---|
| WN11-00-000005 | Domain-joined systems must use Win 11 Enterprise 64-bit | II |
| WN11-00-000030 | BitLocker must protect the OS drive | I |
| WN11-00-000031 | BitLocker PIN required for pre-boot authentication | I |
| WN11-00-000032 | BitLocker PIN minimum length of 6 digits | II |
| WN11-00-000040 | System must be at a supported servicing level | I |
| WN11-00-000050 | Local volumes must be formatted NTFS | I |
| WN11-00-000100 | IIS must not be installed | I |
| WN11-00-000110 | Simple TCP/IP Services must not be installed | II |
| WN11-00-000115 | Telnet Client must not be installed | II |
| WN11-00-000120 | TFTP Client must not be installed | II |
| WN11-00-000150 | SEHOP must be enabled | I |
| WN11-00-000155 | PowerShell 2.0 must be disabled | II |
| WN11-00-000160 | SMB v1 must be disabled | II |
| WN11-00-000165 | SMB v1 client driver must be disabled | II |
| WN11-00-000170 | SMB v1 server must be disabled | II |
| WN11-00-000175 | Secondary Logon service must be disabled | II |
| WN11-00-000126 | Consumer account user authentication must be blocked | II |

### Check-AccountPolicy.ps1 — WN11-AC-*

Password policy and account lockout settings via `net accounts` and `secedit`.

| STIG ID | Title | CAT |
|---|---|---|
| WN11-AC-000005 | Lockout duration ≥ 15 minutes | II |
| WN11-AC-000010 | Lockout threshold ≤ 3 attempts | II |
| WN11-AC-000015 | Reset lockout counter ≥ 15 minutes | II |
| WN11-AC-000020 | Password history ≥ 24 | II |
| WN11-AC-000025 | Maximum password age ≤ 60 days | II |
| WN11-AC-000030 | Minimum password age ≥ 1 day | II |
| WN11-AC-000035 | Minimum password length ≥ 14 characters | II |
| WN11-AC-000040 | Password complexity must be enabled | II |
| WN11-AC-000045 | Reversible password encryption must be disabled | I |

### Check-AuditPolicy.ps1 — WN11-AU-*

Audit subcategory configuration via `auditpol` and event log size via registry. 53 controls covering Credential Validation, Logon/Logoff, Process Creation, Object Access, Policy Change, Privilege Use, System, and more.

Key controls include: WN11-AU-000005 through WN11-AU-000589, plus event log size minimums (WN11-AU-000500/505/510 → 32768 KB / 196608 KB / 32768 KB).

### Check-CCSettings.ps1 — WN11-CC-*, WN11-EP-*, WN11-PK-*

Registry/Group Policy settings. 76 controls covering autoplay, screen lock, WinRM, Remote Desktop, PowerShell logging, SmartScreen, UAC behavior, Wi-Fi Sense, telemetry, Credential Guard, DMA protection, and more.

Selected highlights:

| STIG ID | Title | CAT |
|---|---|---|
| WN11-CC-000155 | Solicited Remote Assistance must not be allowed | I |
| WN11-CC-000180 | Autoplay off for non-volume devices | I |
| WN11-CC-000185 | Default autorun must prevent autorun commands | I |
| WN11-CC-000190 | Autoplay must be disabled for all drives | I |
| WN11-CC-000315 | Windows Installer "always install elevated" must be disabled | I |
| WN11-CC-000326 | PowerShell Script Block Logging must be enabled | II |
| WN11-CC-000327 | PowerShell Transcription must be enabled | II |
| WN11-CC-000330 | WinRM client must not use Basic authentication | I |
| WN11-CC-000345 | WinRM service must not use Basic authentication | I |
| WN11-EP-000310 | Kernel DMA Protection must be enabled | II |

### Check-SecurityOptions.ps1 — WN11-SO-*

LSA, NTLM, Kerberos, SMB signing, UAC, secure channel, FIPS. 40 controls.

Selected highlights:

| STIG ID | Title | CAT |
|---|---|---|
| WN11-SO-000145 | Anonymous SAM enumeration must not be allowed | I |
| WN11-SO-000150 | Anonymous share enumeration must be restricted | I |
| WN11-SO-000165 | Anonymous access to Named Pipes/Shares must be restricted | I |
| WN11-SO-000195 | LM hash storage must be disabled | I |
| WN11-SO-000205 | LanMan auth level must be NTLMv2 only | I |
| WN11-SO-000270 | UAC must run all admins in Admin Approval Mode | II |

### Check-UserRights.ps1 — WN11-UR-*

User Rights Assignment via `secedit` export. 29 controls. Exports policy once per run to minimize overhead.

| STIG ID | Title | CAT |
|---|---|---|
| WN11-UR-000015 | "Act as part of the operating system" must be empty | I |
| WN11-UR-000045 | "Create a token object" must be empty | I |
| WN11-UR-000065 | "Debug programs" — Administrators only | I |
| WN11-UR-000095 | "Enable delegation" must not be assigned | II |
| WN11-UR-000125 | "Lock pages in memory" must not be assigned | II |

### Check-Miscellaneous.ps1 — WN11-UC-*

Per-user configuration (HKCU) settings: lock screen notifications, zone information preservation.

### Check-Firewall.ps1 — WNFWA-* (Firewall V2R3)

All 20 controls from the Windows Defender Firewall STIG. Checks are performed via `Get-NetFirewallProfile` with a registry fallback for environments where the cmdlet is unavailable. Each of the three profiles (Domain, Private, Public) is evaluated independently.

| STIG ID | Title | CAT |
|---|---|---|
| WNFWA-000001 | Firewall enabled — Domain | II |
| WNFWA-000002 | Firewall enabled — Private | II |
| WNFWA-000003 | Firewall enabled — Public | II |
| WNFWA-000004 | Block unsolicited inbound — Domain | I |
| WNFWA-000005 | Allow outbound unless blocked — Domain | II |
| WNFWA-000009 | Log size ≥ 16384 KB — Domain | III |
| WNFWA-000010 | Log dropped packets — Domain | III |
| WNFWA-000011 | Log successful connections — Domain | III |
| WNFWA-000012 | Block unsolicited inbound — Private | I |
| WNFWA-000013 | Allow outbound unless blocked — Private | II |
| WNFWA-000017 | Log size ≥ 16384 KB — Private | III |
| WNFWA-000018 | Log dropped packets — Private | III |
| WNFWA-000019 | Log successful connections — Private | III |
| WNFWA-000020 | Block unsolicited inbound — Public | I |
| WNFWA-000021 | Allow outbound unless blocked — Public | II |
| WNFWA-000024 | Local FW rules must not merge with GPO — Public | II |
| WNFWA-000025 | Local IPsec rules must not merge with GPO — Public | II |
| WNFWA-000027 | Log size ≥ 16384 KB — Public | III |
| WNFWA-000028 | Log dropped packets — Public | III |
| WNFWA-000029 | Log successful connections — Public | III |

---

## Severity Guide

| Category | Label | Meaning | Response |
|---|---|---|---|
| CAT I | Critical | Direct, immediate risk of system compromise | Remediate immediately |
| CAT II | High | Significant risk if exploited | Remediate within standard patch cycle |
| CAT III | Low/Moderate | Defense-in-depth control; limited standalone impact | Remediate as resources allow |

Findings marked **Manual** require human review and cannot be evaluated programmatically. Findings marked **Error** indicate the check itself failed — typically due to a missing cmdlet or insufficient privilege on a specific control.

---

## Adding New Checks

1. Create `scripts/modules/Check-<Category>.ps1`
2. Follow the module pattern — return a `List[PSObject]` using the `New-Finding` helper with all required fields: `stig_id`, `title`, `severity`, `description`, `check`, `fix`, `pass_criteria`, `status`, `evidence`
3. Add the filename to the `$modules` array in `Invoke-STIGAssessment.ps1`

**Skeleton:**

```powershell
$findings = [System.Collections.Generic.List[PSObject]]::new()

function New-Finding {
    param($StigId,$Title,$Severity,$Description,$Check,$Fix,$PassCriteria,$Status,$Evidence="")
    [PSCustomObject]@{
        stig_id       = $StigId
        title         = $Title
        severity      = $Severity      # CAT_I | CAT_II | CAT_III
        description   = $Description
        check         = $Check
        fix           = $Fix
        pass_criteria = $PassCriteria
        status        = $Status        # Pass | Fail | Manual | Error
        evidence      = $Evidence
    }
}

# ... your check logic ...

return $findings
```

---

## Known Limitations

- **Domain-joined systems:** Some checks (password policy, lockout) read local policy via `net accounts`. On domain-joined machines, effective policy comes from Group Policy and may differ from what these commands report. Supplement with a domain-level STIG assessment.
- **BitLocker cmdlet availability:** `Get-BitLockerVolume` requires the BitLocker feature to be installed. The encryption module falls back to `manage-bde` automatically if the cmdlet is absent.
- **HKCU checks:** Screen saver settings are per-user (`HKCU`). Run the assessment as the interactive user, or deploy via Group Policy for consistent enforcement.
- **Manual controls:** Some STIG controls (e.g., physical security, documentation requirements) cannot be automated. These are marked `Manual` in the output and require a human reviewer.
- **STIG version drift:** DISA publishes STIG updates periodically. Verify STIG IDs and pass criteria against the current benchmark at [public.cyber.mil/stigs](https://public.cyber.mil/stigs/) before using findings in a formal Assessment & Authorization (A&A) package.

---

## License

This project is internal tooling for cybersecurity assessment purposes. Not affiliated with or endorsed by DISA. Always validate findings against the official STIG benchmark before submitting to an authorizing official.
