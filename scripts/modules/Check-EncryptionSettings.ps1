<#
.SYNOPSIS
    STIG Encryption / BitLocker / TLS checks for Windows 11 (WN11 V1R4)
.DESCRIPTION
    Checks BitLocker drive encryption status, TPM presence, and system
    drive encryption. Also verifies TLS/SSL registry configurations.
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

# ── WN11-00-000030 : BitLocker on OS drive ────────────────────────────────────
try {
    $blStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $status   = if ($blStatus.ProtectionStatus -eq "On") { "Pass" } else { "Fail" }
    $evidence = "Drive: $($blStatus.MountPoint) | Protection: $($blStatus.ProtectionStatus) | VolumeStatus: $($blStatus.VolumeStatus)"
    $findings.Add((New-Finding `
        -StigId      "WN11-00-000030" `
        -Title       "BitLocker must protect the OS drive" `
        -Severity    "CAT_I" `
        -Description "Without full-volume encryption, data is accessible if physical media is removed." `
        -Check       "Get-BitLockerVolume -MountPoint C:" `
        -Fix         "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -TpmProtector" `
        -PassCriteria "ProtectionStatus = On" `
        -Status      $status `
        -Evidence    $evidence
    ))
} catch {
    # BitLocker cmdlet unavailable on some SKUs; fall back to manage-bde
    try {
        $bdeOut = manage-bde -status $env:SystemDrive 2>&1
        $protLine = $bdeOut | Where-Object { $_ -match "Protection Status" }
        $protVal  = if ($protLine) { $protLine } else { "Unknown" }
        $status   = if ($protLine -and $protLine -match "Protection On") { "Pass" } else { "Fail" }
        $findings.Add((New-Finding `
            -StigId      "WN11-00-000030" `
            -Title       "BitLocker must protect the OS drive" `
            -Severity    "CAT_I" `
            -Description "Without full-volume encryption, data is accessible if physical media is removed." `
            -Check       "manage-bde -status C:" `
            -Fix         "manage-bde -on C: -RecoveryPassword" `
            -PassCriteria "Protection Status: Protection On" `
            -Status      $status `
            -Evidence    ($protVal | Out-String).Trim()
        ))
    } catch {
        $findings.Add((New-Finding "WN11-00-000030" "BitLocker OS drive" "CAT_I" "" "" "" "" "Error" $_.ToString()))
    }
}

# ── WN11-00-000031 : TPM presence and enabled ─────────────────────────────────
try {
    $tpm    = Get-Tpm -ErrorAction Stop
    $status = if ($tpm.TpmPresent -and $tpm.TpmEnabled) { "Pass" } else { "Fail" }
    $evidence = "Present: $($tpm.TpmPresent) | Enabled: $($tpm.TpmEnabled) | Activated: $($tpm.TpmActivated) | Owned: $($tpm.TpmOwned)"
    $findings.Add((New-Finding `
        -StigId      "WN11-00-000031" `
        -Title       "TPM must be present and enabled" `
        -Severity    "CAT_II" `
        -Description "TPM provides hardware-based key protection for BitLocker and Secure Boot." `
        -Check       "Get-Tpm" `
        -Fix         "Enable TPM in BIOS/UEFI settings. Ensure TPM 2.0 is present and active." `
        -PassCriteria "TpmPresent = True AND TpmEnabled = True" `
        -Status      $status `
        -Evidence    $evidence
    ))
} catch {
    $findings.Add((New-Finding "WN11-00-000031" "TPM presence" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-CC-000052 : TLS 1.0 disabled ────────────────────────────────────────
try {
    $tls10Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
    $tls10Exist = Test-Path $tls10Path
    $tls10Val   = if ($tls10Exist) { (Get-ItemProperty $tls10Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled } else { $null }
    # Compliant if key is absent OR explicitly set to 0
    $status     = if (-not $tls10Exist -or $tls10Val -eq 0) { "Pass" } else { "Fail" }
    $evidence   = if ($tls10Exist) { "TLS 1.0 Client Enabled = $tls10Val" } else { "Registry key absent (disabled by default)" }
    $findings.Add((New-Finding `
        -StigId      "WN11-CC-000052" `
        -Title       "TLS 1.0 must be disabled" `
        -Severity    "CAT_II" `
        -Description "TLS 1.0 contains known vulnerabilities (POODLE, BEAST) and must not be used." `
        -Check       "HKLM:\...\SCHANNEL\Protocols\TLS 1.0\Client - Enabled value" `
        -Fix         "New-Item -Path 'HKLM:\...\Protocols\TLS 1.0\Client' -Force; Set-ItemProperty ... -Name 'Enabled' -Value 0" `
        -PassCriteria "Key absent or Enabled = 0" `
        -Status      $status `
        -Evidence    $evidence
    ))
} catch {
    $findings.Add((New-Finding "WN11-CC-000052" "TLS 1.0 disabled" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-CC-000053 : TLS 1.1 disabled ────────────────────────────────────────
try {
    $tls11Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
    $tls11Exist = Test-Path $tls11Path
    $tls11Val   = if ($tls11Exist) { (Get-ItemProperty $tls11Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled } else { $null }
    $status     = if (-not $tls11Exist -or $tls11Val -eq 0) { "Pass" } else { "Fail" }
    $evidence   = if ($tls11Exist) { "TLS 1.1 Client Enabled = $tls11Val" } else { "Registry key absent (disabled by default)" }
    $findings.Add((New-Finding `
        -StigId      "WN11-CC-000053" `
        -Title       "TLS 1.1 must be disabled" `
        -Severity    "CAT_II" `
        -Description "TLS 1.1 is deprecated and susceptible to downgrade attacks." `
        -Check       "HKLM:\...\SCHANNEL\Protocols\TLS 1.1\Client - Enabled value" `
        -Fix         "New-Item -Path 'HKLM:\...\Protocols\TLS 1.1\Client' -Force; Set-ItemProperty ... -Name 'Enabled' -Value 0" `
        -PassCriteria "Key absent or Enabled = 0" `
        -Status      $status `
        -Evidence    $evidence
    ))
} catch {
    $findings.Add((New-Finding "WN11-CC-000053" "TLS 1.1 disabled" "CAT_II" "" "" "" "" "Error" $_.ToString()))
}

# ── WN11-CC-000054 : SSL 3.0 disabled ────────────────────────────────────────
try {
    $ssl3Path  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
    $ssl3Exist = Test-Path $ssl3Path
    $ssl3Val   = if ($ssl3Exist) { (Get-ItemProperty $ssl3Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled } else { $null }
    $status    = if (-not $ssl3Exist -or $ssl3Val -eq 0) { "Pass" } else { "Fail" }
    $evidence  = if ($ssl3Exist) { "SSL 3.0 Client Enabled = $ssl3Val" } else { "Registry key absent (disabled by default)" }
    $findings.Add((New-Finding `
        -StigId      "WN11-CC-000054" `
        -Title       "SSL 3.0 must be disabled" `
        -Severity    "CAT_I" `
        -Description "SSL 3.0 is critically vulnerable (POODLE) and must be completely disabled." `
        -Check       "HKLM:\...\SCHANNEL\Protocols\SSL 3.0\Client - Enabled value" `
        -Fix         "New-Item -Path 'HKLM:\...\Protocols\SSL 3.0\Client' -Force; Set-ItemProperty ... -Name 'Enabled' -Value 0" `
        -PassCriteria "Key absent or Enabled = 0" `
        -Status      $status `
        -Evidence    $evidence
    ))
} catch {
    $findings.Add((New-Finding "WN11-CC-000054" "SSL 3.0 disabled" "CAT_I" "" "" "" "" "Error" $_.ToString()))
}

return $findings
