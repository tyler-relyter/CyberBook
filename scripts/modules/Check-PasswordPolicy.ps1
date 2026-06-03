<#
.SYNOPSIS
    STIG Password Policy checks for Windows 11 (WN11 V1R4)
.DESCRIPTION
    Returns an array of finding objects. Each object conforms to the
    CyberBook SKILL.md schema: stig_id, title, severity, description,
    check, fix, pass_criteria, status, evidence.
#>

$findings = [System.Collections.Generic.List[PSObject]]::new()

function New-Finding {
    param($StigId,$Title,$Severity,$Description,$Check,$Fix,$PassCriteria,$Status,$Evidence="")
    [PSCustomObject]@{
        stig_id       = $StigId
        title         = $Title
        severity      = $Severity
        description   = $Description
        check         = $Check
        fix           = $Fix
        pass_criteria = $PassCriteria
        status        = $Status
        evidence      = $Evidence
    }
}

# Pull net accounts policy once
$netAccounts = net accounts 2>&1

function Get-NetAccountsValue {
    param([string]$Label)
    $line = $netAccounts | Where-Object { $_ -match $Label }
    if ($line) { ($line -split ":")[1].Trim() } else { "UNKNOWN" }
}

# ── WN11-AC-000010 : Maximum password age ─────────────────────────────────────
try {
    $maxAge = Get-NetAccountsValue "Maximum password age"
    $maxAgeInt = if ($maxAge -match '^\d+$') { [int]$maxAge } else { 999 }
    $status = if ($maxAgeInt -le 60 -and $maxAgeInt -gt 0) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000010" `
        -Title       "Maximum password age must be 60 days or less" `
        -Severity    "CAT_II" `
        -Description "Passwords that do not expire increase exposure time of a compromised credential." `
        -Check       "net accounts | find 'Maximum password age'" `
        -Fix         "net accounts /maxpwage:60" `
        -PassCriteria "Value <= 60 and > 0" `
        -Status      $status `
        -Evidence    "Maximum password age: $maxAge"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000010" "Maximum password age" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000020 : Minimum password age ─────────────────────────────────────
try {
    $minAge = Get-NetAccountsValue "Minimum password age"
    $minAgeInt = if ($minAge -match '^\d+$') { [int]$minAge } else { 0 }
    $status = if ($minAgeInt -ge 1) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000020" `
        -Title       "Minimum password age must be at least 1 day" `
        -Severity    "CAT_II" `
        -Description "Prevents users from immediately cycling back to a previous password." `
        -Check       "net accounts | find 'Minimum password age'" `
        -Fix         "net accounts /minpwage:1" `
        -PassCriteria "Value >= 1" `
        -Status      $status `
        -Evidence    "Minimum password age: $minAge"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000020" "Minimum password age" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000030 : Minimum password length ──────────────────────────────────
try {
    $minLen = Get-NetAccountsValue "Minimum password length"
    $minLenInt = if ($minLen -match '^\d+$') { [int]$minLen } else { 0 }
    $status = if ($minLenInt -ge 14) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000030" `
        -Title       "Minimum password length must be 14 characters or more" `
        -Severity    "CAT_II" `
        -Description "Short passwords are susceptible to brute-force attacks." `
        -Check       "net accounts | find 'Minimum password length'" `
        -Fix         "net accounts /minpwlen:14" `
        -PassCriteria "Value >= 14" `
        -Status      $status `
        -Evidence    "Minimum password length: $minLen"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000030" "Minimum password length" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000040 : Password history ─────────────────────────────────────────
try {
    $history = Get-NetAccountsValue "Length of password history maintained"
    $historyInt = if ($history -match '^\d+$') { [int]$history } else { 0 }
    $status = if ($historyInt -ge 24) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000040" `
        -Title       "Password history must be at least 24 passwords" `
        -Severity    "CAT_II" `
        -Description "Prevents reuse of recent passwords, reducing risk from credential replay." `
        -Check       "net accounts | find 'Length of password history'" `
        -Fix         "net accounts /uniquepw:24" `
        -PassCriteria "Value >= 24" `
        -Status      $status `
        -Evidence    "Password history length: $history"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000040" "Password history" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000050 : Password complexity via secedit ─────────────────────────
try {
    $tmpFile = "$env:TEMP\secpol_$PID.cfg"
    secedit /export /cfg $tmpFile /quiet 2>&1 | Out-Null
    $secContent = Get-Content $tmpFile -ErrorAction Stop
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

    $complexLine = $secContent | Where-Object { $_ -match "PasswordComplexity\s*=" }
    $complexVal  = if ($complexLine) { ($complexLine -split "=")[1].Trim() } else { "0" }
    $status = if ($complexVal -eq "1") { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000050" `
        -Title       "Password complexity must be enabled" `
        -Severity    "CAT_II" `
        -Description "Complexity requirements (uppercase, lowercase, digit, symbol) reduce guessability." `
        -Check       "secedit /export /cfg <tmp> then check PasswordComplexity" `
        -Fix         "Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> Password must meet complexity requirements: Enabled" `
        -PassCriteria "PasswordComplexity = 1" `
        -Status      $status `
        -Evidence    "PasswordComplexity = $complexVal"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000050" "Password complexity" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

return $findings
