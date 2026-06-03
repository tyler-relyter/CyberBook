<#
.SYNOPSIS
    STIG Account Lockout Policy checks for Windows 11 (WN11 V1R4)
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

$netAccounts = net accounts 2>&1

function Get-NetVal([string]$Label) {
    $line = $netAccounts | Where-Object { $_ -match $Label }
    if ($line) { ($line -split ":")[1].Trim() } else { "UNKNOWN" }
}

# ── WN11-AC-000060 : Lockout threshold ────────────────────────────────────────
try {
    $threshold    = Get-NetVal "Lockout threshold"
    $thresholdInt = if ($threshold -match '^\d+$') { [int]$threshold } else { 0 }
    $status       = if ($thresholdInt -ge 1 -and $thresholdInt -le 3) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000060" `
        -Title       "Account lockout threshold must be 3 or fewer invalid logon attempts" `
        -Severity    "CAT_II" `
        -Description "Unlimited logon attempts enable brute-force attacks against local accounts." `
        -Check       "net accounts | find 'Lockout threshold'" `
        -Fix         "net accounts /lockoutthreshold:3" `
        -PassCriteria "1 <= Value <= 3" `
        -Status      $status `
        -Evidence    "Lockout threshold: $threshold"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000060" "Account lockout threshold" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000070 : Lockout duration ─────────────────────────────────────────
try {
    $duration    = Get-NetVal "Lockout duration"
    $durationInt = if ($duration -match '^\d+$') { [int]$duration } else { 0 }
    # STIG requires >= 15 minutes (0 = forever, which is also acceptable)
    $status      = if ($durationInt -ge 15 -or $durationInt -eq 0) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000070" `
        -Title       "Account lockout duration must be 15 minutes or greater" `
        -Severity    "CAT_II" `
        -Description "Short lockout durations allow rapid retry after lockout, reducing brute-force protection." `
        -Check       "net accounts | find 'Lockout duration'" `
        -Fix         "net accounts /lockoutduration:15" `
        -PassCriteria "Value >= 15 or Value = 0 (never unlocks automatically)" `
        -Status      $status `
        -Evidence    "Lockout duration: $duration minutes"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000070" "Account lockout duration" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000080 : Lockout observation window ───────────────────────────────
try {
    $window    = Get-NetVal "Lockout observation window"
    $windowInt = if ($window -match '^\d+$') { [int]$window } else { 0 }
    $status    = if ($windowInt -ge 15) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000080" `
        -Title       "Reset account lockout counter must be 15 minutes or greater" `
        -Severity    "CAT_II" `
        -Description "A short observation window allows rapid password spraying while avoiding lockout." `
        -Check       "net accounts | find 'Lockout observation window'" `
        -Fix         "net accounts /lockoutwindow:15" `
        -PassCriteria "Value >= 15" `
        -Status      $status `
        -Evidence    "Lockout observation window: $window minutes"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000080" "Lockout observation window" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-AC-000090 : Guest account disabled ───────────────────────────────────
try {
    $guest  = Get-LocalUser -Name "Guest" -ErrorAction Stop
    $status = if (-not $guest.Enabled) { "Pass" } else { "Fail" }
    $findings.Add((New-Finding `
        -StigId      "WN11-AC-000090" `
        -Title       "The built-in Guest account must be disabled" `
        -Severity    "CAT_I" `
        -Description "The Guest account provides unauthenticated access and must be disabled." `
        -Check       "Get-LocalUser -Name 'Guest' | Select-Object Enabled" `
        -Fix         "Disable-LocalUser -Name 'Guest'" `
        -PassCriteria "Enabled = False" `
        -Status      $status `
        -Evidence    "Guest account Enabled: $($guest.Enabled)"
    ))
} catch {
    $findings.Add((New-Finding "WN11-AC-000090" "Guest account disabled" "CAT_I" "" "" "" "" "Error" $_.ToString()))
}

return $findings
