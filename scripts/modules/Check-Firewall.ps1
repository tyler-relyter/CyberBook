#Requires -Version 5.0
# AUTO-GENERATED from DISA STIG Windows Defender Firewall V2R3
# Source: U_MS_Windows_Defender_Firewall_V2R3_STIG_SCAP_1-2_Benchmark.xml

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

# Helper: query a single firewall profile via Get-NetFirewallProfile
function Get-FWProfile([string]$ProfileName) {
    try {
        return Get-NetFirewallProfile -Profile $ProfileName -ErrorAction Stop
    } catch {
        return $null
    }
}

# Helper: read from policy registry path first, fall back to runtime path
function Get-FWRegValue([string]$Profile, [string]$SubKey, [string]$Name) {
    $policyBase = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"
    $runtimeBase = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    $runtimeProfile = switch ($Profile) {
        'Domain'  { 'DomainProfile' }
        'Private' { 'StandardProfile' }
        'Public'  { 'PublicProfile' }
    }
    $policyPath  = if ($SubKey) { "$policyBase\${Profile}Profile\$SubKey" } else { "$policyBase\${Profile}Profile" }
    $runtimePath = if ($SubKey) { "$runtimeBase\$runtimeProfile\$SubKey" } else { "$runtimeBase\$runtimeProfile" }

    $val = (Get-ItemProperty -Path $policyPath  -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -eq $val) {
        $val = (Get-ItemProperty -Path $runtimePath -Name $Name -ErrorAction SilentlyContinue).$Name
    }
    return $val
}

# ==========================================================
# Firewall Enabled  (WNFWA-000001 / 000002 / 000003)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000001'; Profile='Domain';  Severity='CAT_II' },
    @{ StigId='WNFWA-000002'; Profile='Private'; Severity='CAT_II' },
    @{ StigId='WNFWA-000003'; Profile='Public';  Severity='CAT_II' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile '' 'EnableFirewall'
        # Compliant if Get-NetFirewallProfile says Enabled OR registry key = 1
        $fwEnabled = ($null -ne $prof -and $prof.Enabled -eq $true) -or ($regVal -eq 1)
        $status = if ($fwEnabled) { 'Pass' } else { 'Fail' }
        $evidence = if ($null -ne $prof) {
            "$($entry.Profile) profile Enabled=$($prof.Enabled) | Registry EnableFirewall=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        } else {
            "Get-NetFirewallProfile unavailable | Registry EnableFirewall=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall must be enabled when connected to a $($entry.Profile) network." `
            -Severity     $entry.Severity `
            -Description  "An inactive firewall exposes the system to attack. Windows Defender Firewall is a host-based firewall that can be used in conjunction with other security measures." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select Enabled" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -Enabled True" `
            -PassCriteria "Enabled = True" `
            -Status       $status `
            -Evidence     $evidence
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Firewall enabled ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Block Unsolicited Inbound  (WNFWA-000004 / 000012 / 000020)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000004'; Profile='Domain';  Severity='CAT_I' },
    @{ StigId='WNFWA-000012'; Profile='Private'; Severity='CAT_I' },
    @{ StigId='WNFWA-000020'; Profile='Public';  Severity='CAT_I' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile '' 'DefaultInboundAction'
        # NetFirewallProfile: DefaultInboundAction = 'Block' (2)
        # Registry: DefaultInboundAction = 1 (Block) or 2 (Block) depending on encoding
        $isBlock = ($null -ne $prof -and $prof.DefaultInboundAction -eq 'Block') -or ($regVal -eq 1 -or $regVal -eq 2)
        $status  = if ($isBlock) { 'Pass' } else { 'Fail' }
        $evidence = if ($null -ne $prof) {
            "$($entry.Profile) DefaultInboundAction=$($prof.DefaultInboundAction) | Registry=$( if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        } else {
            "Registry DefaultInboundAction=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall must block unsolicited inbound connections on the $($entry.Profile) profile." `
            -Severity     $entry.Severity `
            -Description  "A firewall provides a line of defense against attack. Unsolicited inbound connections must be blocked to reduce the attack surface." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select DefaultInboundAction" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -DefaultInboundAction Block" `
            -PassCriteria "DefaultInboundAction = Block" `
            -Status       $status `
            -Evidence     $evidence
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Block inbound ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Allow Outbound Unless Blocked  (WNFWA-000005 / 000013 / 000021)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000005'; Profile='Domain';  Severity='CAT_II' },
    @{ StigId='WNFWA-000013'; Profile='Private'; Severity='CAT_II' },
    @{ StigId='WNFWA-000021'; Profile='Public';  Severity='CAT_II' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile '' 'DefaultOutboundAction'
        # Compliant: DefaultOutboundAction = Allow (0) — block-by-default would fail outbound
        $isAllow = ($null -ne $prof -and $prof.DefaultOutboundAction -eq 'Allow') -or ($regVal -eq 0)
        $status  = if ($isAllow) { 'Pass' } else { 'Fail' }
        $evidence = if ($null -ne $prof) {
            "$($entry.Profile) DefaultOutboundAction=$($prof.DefaultOutboundAction) | Registry=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        } else {
            "Registry DefaultOutboundAction=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall must allow outbound connections on the $($entry.Profile) profile unless a rule explicitly blocks them." `
            -Severity     $entry.Severity `
            -Description  "If outbound connections are blocked by default, critical network services and updates may fail. The STIG requires outbound Allow as the default action." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select DefaultOutboundAction" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -DefaultOutboundAction Allow" `
            -PassCriteria "DefaultOutboundAction = Allow" `
            -Status       $status `
            -Evidence     $evidence
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Allow outbound ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Log Size >= 16384 KB  (WNFWA-000009 / 000017 / 000027)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000009'; Profile='Domain';  Severity='CAT_III' },
    @{ StigId='WNFWA-000017'; Profile='Private'; Severity='CAT_III' },
    @{ StigId='WNFWA-000027'; Profile='Public';  Severity='CAT_III' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile 'Logging' 'LogFileSize'
        # Get-NetFirewallProfile returns LogMaxSizeKilobytes
        $sizeKB = if ($null -ne $prof -and $prof.LogMaxSizeKilobytes -gt 0) {
            $prof.LogMaxSizeKilobytes
        } elseif ($null -ne $regVal) {
            [int]$regVal
        } else { 0 }
        $status   = if ($sizeKB -ge 16384) { 'Pass' } else { 'Fail' }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall log size must be at least 16384 KB for the $($entry.Profile) profile." `
            -Severity     $entry.Severity `
            -Description  "The firewall log must be large enough to retain security-relevant events without rolling over too quickly." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select LogMaxSizeKilobytes" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -LogMaxSizeKilobytes 16384" `
            -PassCriteria "LogMaxSizeKilobytes >= 16384" `
            -Status       $status `
            -Evidence     "$($entry.Profile) log size: ${sizeKB} KB"
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Log size ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Log Dropped Packets  (WNFWA-000010 / 000018 / 000028)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000010'; Profile='Domain';  Severity='CAT_III' },
    @{ StigId='WNFWA-000018'; Profile='Private'; Severity='CAT_III' },
    @{ StigId='WNFWA-000028'; Profile='Public';  Severity='CAT_III' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile 'Logging' 'LogDroppedPackets'
        # LogBlocked in Get-NetFirewallProfile; registry value 1 = Yes
        $isEnabled = ($null -ne $prof -and $prof.LogBlocked -eq 'True') -or ($regVal -eq 1)
        $status    = if ($isEnabled) { 'Pass' } else { 'Fail' }
        $profVal   = if ($null -ne $prof) { $prof.LogBlocked } else { 'N/A' }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall must log dropped packets for the $($entry.Profile) profile." `
            -Severity     $entry.Severity `
            -Description  "Logging of dropped packets provides visibility into blocked connection attempts and potential intrusion activity." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select LogBlocked" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -LogBlocked True" `
            -PassCriteria "LogBlocked = True" `
            -Status       $status `
            -Evidence     "$($entry.Profile) LogBlocked=$profVal | Registry LogDroppedPackets=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Log dropped ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Log Successful Connections  (WNFWA-000011 / 000019 / 000029)
# ==========================================================

foreach ($entry in @(
    @{ StigId='WNFWA-000011'; Profile='Domain';  Severity='CAT_III' },
    @{ StigId='WNFWA-000019'; Profile='Private'; Severity='CAT_III' },
    @{ StigId='WNFWA-000029'; Profile='Public';  Severity='CAT_III' }
)) {
    try {
        $prof   = Get-FWProfile $entry.Profile
        $regVal = Get-FWRegValue $entry.Profile 'Logging' 'LogSuccessfulConnections'
        $isEnabled = ($null -ne $prof -and $prof.LogAllowed -eq 'True') -or ($regVal -eq 1)
        $status    = if ($isEnabled) { 'Pass' } else { 'Fail' }
        $profVal   = if ($null -ne $prof) { $prof.LogAllowed } else { 'N/A' }
        $findings.Add((New-Finding `
            -StigId       $entry.StigId `
            -Title        "Windows Defender Firewall must log successful connections for the $($entry.Profile) profile." `
            -Severity     $entry.Severity `
            -Description  "Logging of allowed connections supports post-incident forensic analysis and threat hunting." `
            -Check        "Get-NetFirewallProfile -Profile $($entry.Profile) | Select LogAllowed" `
            -Fix          "Set-NetFirewallProfile -Profile $($entry.Profile) -LogAllowed True" `
            -PassCriteria "LogAllowed = True" `
            -Status       $status `
            -Evidence     "$($entry.Profile) LogAllowed=$profVal | Registry LogSuccessfulConnections=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
        ))
    } catch {
        $findings.Add((New-Finding $entry.StigId "Log allowed ($($entry.Profile))" $entry.Severity '' '' '' '' 'Error' $_.ToString()))
    }
}

# ==========================================================
# Local Firewall Rules Not Merged - Public (WNFWA-000024)
# ==========================================================

try {
    $prof   = Get-FWProfile 'Public'
    $regVal = Get-FWRegValue 'Public' '' 'AllowLocalPolicyMerge'
    # Compliant: AllowLocalFirewallRules = False (0)
    $isMergeDisabled = ($null -ne $prof -and $prof.AllowLocalFirewallRules -eq 'False') -or ($regVal -eq 0)
    $status = if ($isMergeDisabled) { 'Pass' } else { 'Fail' }
    $profVal = if ($null -ne $prof) { $prof.AllowLocalFirewallRules } else { 'N/A' }
    $findings.Add((New-Finding `
        -StigId       'WNFWA-000024' `
        -Title        'Windows Defender Firewall local firewall rules must not be merged with Group Policy on the Public profile.' `
        -Severity     'CAT_II' `
        -Description  'Locally defined rules could allow unintended traffic when connected to a public network. Group Policy must govern all public-profile rules.' `
        -Check        'Get-NetFirewallProfile -Profile Public | Select AllowLocalFirewallRules' `
        -Fix          'Set-NetFirewallProfile -Profile Public -AllowLocalFirewallRules False' `
        -PassCriteria 'AllowLocalFirewallRules = False' `
        -Status       $status `
        -Evidence     "Public AllowLocalFirewallRules=$profVal | Registry AllowLocalPolicyMerge=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
    ))
} catch {
    $findings.Add((New-Finding 'WNFWA-000024' 'Local FW rules not merged (Public)' 'CAT_II' '' '' '' '' 'Error' $_.ToString()))
}

# ==========================================================
# Local Connection Rules Not Merged - Public (WNFWA-000025)
# ==========================================================

try {
    $prof   = Get-FWProfile 'Public'
    $regVal = Get-FWRegValue 'Public' '' 'AllowLocalIPsecPolicyMerge'
    $isMergeDisabled = ($null -ne $prof -and $prof.AllowLocalIPsecRules -eq 'False') -or ($regVal -eq 0)
    $status = if ($isMergeDisabled) { 'Pass' } else { 'Fail' }
    $profVal = if ($null -ne $prof) { $prof.AllowLocalIPsecRules } else { 'N/A' }
    $findings.Add((New-Finding `
        -StigId       'WNFWA-000025' `
        -Title        'Windows Defender Firewall local connection security rules must not be merged with Group Policy on the Public profile.' `
        -Severity     'CAT_II' `
        -Description  'Locally defined IPsec connection rules could weaken security when connected to a public network. Group Policy must be the sole source of connection security rules.' `
        -Check        'Get-NetFirewallProfile -Profile Public | Select AllowLocalIPsecRules' `
        -Fix          'Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False' `
        -PassCriteria 'AllowLocalIPsecRules = False' `
        -Status       $status `
        -Evidence     "Public AllowLocalIPsecRules=$profVal | Registry AllowLocalIPsecPolicyMerge=$(if ($null -ne $regVal) { $regVal } else { 'NOT SET' })"
    ))
} catch {
    $findings.Add((New-Finding 'WNFWA-000025' 'Local IPsec rules not merged (Public)' 'CAT_II' '' '' '' '' 'Error' $_.ToString()))
}

return $findings
