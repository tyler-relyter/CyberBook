<#
.SYNOPSIS
    STIG User Rights Assignment checks for Windows 11 (WN11 V1R4)
.DESCRIPTION
    Exports security policy via secedit and verifies that sensitive
    user rights are not granted to inappropriate principals.
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

# Export secedit config once
$tmpCfg = "$env:TEMP\ura_$PID.cfg"
try {
    secedit /export /cfg $tmpCfg /quiet 2>&1 | Out-Null
    $secLines = Get-Content $tmpCfg -ErrorAction Stop
    Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
} catch {
    # If secedit export fails, mark all URA checks as Error
    @(
        "WN11-UR-000010","WN11-UR-000015","WN11-UR-000020",
        "WN11-UR-000025","WN11-UR-000030"
    ) | ForEach-Object {
        $findings.Add((New-Finding $_ "secedit export failed" "CAT_II" "" "" "" "" "Error" $_.ToString()))
    }
    return $findings
}

function Get-RightValue([string]$Right) {
    $line = $secLines | Where-Object { $_ -match "^$Right\s*=" }
    if ($line) { ($line -split "=",2)[1].Trim() } else { "" }
}

function Contains-Unexpected {
    param([string]$Right, [string[]]$AllowedSids)
    $val = Get-RightValue $Right
    if ([string]::IsNullOrWhiteSpace($val)) { return $false }
    $assigned = $val -split "," | ForEach-Object { $_.Trim() }
    foreach ($a in $assigned) {
        if ($a -notin $AllowedSids) { return $true }
    }
    return $false
}

# ── WN11-UR-000010 : Act as OS – must be empty ────────────────────────────────
try {
    $val    = Get-RightValue "SeTcbPrivilege"
    $status = if ([string]::IsNullOrWhiteSpace($val)) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-UR-000010" `
        -Title       "'Act as part of the operating system' must not be assigned" `
        -Severity    "CAT_I" `
        -Description "This right allows a process to impersonate any user; misuse leads to full system compromise." `
        -Check       "secedit export -> check SeTcbPrivilege" `
        -Fix         "Remove all accounts from: User Rights Assignment -> Act as part of the operating system" `
        -PassCriteria "SeTcbPrivilege value is empty" `
        -Status      $status `
        -Evidence    "SeTcbPrivilege = $(if ($val) { $val } else { '(empty)' })"
    ))
} catch {
    $findings.Add((New-Finding "WN11-UR-000010" "Act as OS right" "CAT_I" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-UR-000015 : Create token object – must be empty ──────────────────────
try {
    $val    = Get-RightValue "SeCreateTokenPrivilege"
    $status = if ([string]::IsNullOrWhiteSpace($val)) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-UR-000015" `
        -Title       "'Create a token object' must not be assigned to any user or group" `
        -Severity    "CAT_I" `
        -Description "This right lets processes create access tokens with arbitrary privileges." `
        -Check       "secedit export -> check SeCreateTokenPrivilege" `
        -Fix         "Remove all entries from: User Rights Assignment -> Create a token object" `
        -PassCriteria "SeCreateTokenPrivilege value is empty" `
        -Status      $status `
        -Evidence    "SeCreateTokenPrivilege = $(if ($val) { $val } else { '(empty)' })"
    ))
} catch {
    $findings.Add((New-Finding "WN11-UR-000015" "Create token object" "CAT_I" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-UR-000020 : Debug programs – Administrators only ─────────────────────
try {
    $val = Get-RightValue "SeDebugPrivilege"
    # Acceptable: only *S-1-5-32-544 (Administrators) or empty
    $nonAdmin = ($val -split ",") | Where-Object { $_.Trim() -ne "" -and $_.Trim() -notmatch "S-1-5-32-544" -and $_.Trim() -notmatch "\*S-1-5-32-544" }
    $status   = if ($nonAdmin.Count -eq 0) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-UR-000020" `
        -Title       "'Debug programs' must only be assigned to Administrators" `
        -Severity    "CAT_II" `
        -Description "Debug access lets a principal read and write to any process memory, enabling credential theft." `
        -Check       "secedit export -> check SeDebugPrivilege" `
        -Fix         "Assign SeDebugPrivilege only to the Administrators group." `
        -PassCriteria "Only *S-1-5-32-544 (Administrators) assigned" `
        -Status      $status `
        -Evidence    "SeDebugPrivilege = $(if ($val) { $val } else { '(empty)' })"
    ))
} catch {
    $findings.Add((New-Finding "WN11-UR-000020" "Debug programs right" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-UR-000025 : Deny logon locally – Guests ──────────────────────────────
try {
    $val = Get-RightValue "SeDenyInteractiveLogonRight"
    # Must include Guest (*S-1-5-32-546)
    $hasGuest = $val -match "S-1-5-32-546"
    $status   = if ($hasGuest) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-UR-000025" `
        -Title       "Guests must be prevented from local logon" `
        -Severity    "CAT_I" `
        -Description "Guest local logon provides unauthenticated interactive access." `
        -Check       "secedit export -> check SeDenyInteractiveLogonRight contains Guests SID" `
        -Fix         "Add Guests (*S-1-5-32-546) to: User Rights Assignment -> Deny log on locally" `
        -PassCriteria "SeDenyInteractiveLogonRight includes *S-1-5-32-546" `
        -Status      $status `
        -Evidence    "SeDenyInteractiveLogonRight = $(if ($val) { $val } else { '(empty)' })"
    ))
} catch {
    $findings.Add((New-Finding "WN11-UR-000025" "Deny guest local logon" "CAT_I" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-UR-000030 : Take ownership – Administrators only ─────────────────────
try {
    $val = Get-RightValue "SeTakeOwnershipPrivilege"
    $nonAdmin = ($val -split ",") | Where-Object { $_.Trim() -ne "" -and $_.Trim() -notmatch "S-1-5-32-544" -and $_.Trim() -notmatch "\*S-1-5-32-544" }
    $status   = if ($nonAdmin.Count -eq 0) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-UR-000030" `
        -Title       "'Take ownership of files' must only be assigned to Administrators" `
        -Severity    "CAT_II" `
        -Description "Take ownership allows bypassing ACL protections on any file or object." `
        -Check       "secedit export -> check SeTakeOwnershipPrivilege" `
        -Fix         "Assign SeTakeOwnershipPrivilege only to Administrators." `
        -PassCriteria "Only *S-1-5-32-544 assigned" `
        -Status      $status `
        -Evidence    "SeTakeOwnershipPrivilege = $(if ($val) { $val } else { '(empty)' })"
    ))
} catch {
    $findings.Add((New-Finding "WN11-UR-000030" "Take ownership right" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

return $findings
