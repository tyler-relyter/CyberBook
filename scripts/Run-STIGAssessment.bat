@echo off
:: ============================================================
::  DISA STIG Windows 11 Assessment Launcher
::  Batch wrapper for Invoke-STIGAssessment.ps1
::  Provides admin elevation, execution policy bypass,
::  and fallback error handling.
:: ============================================================

setlocal EnableDelayedExpansion
title STIG Assessment Tool - Windows 11

:: ── Elevation check ──────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required.
    echo [!] Relaunching with elevation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ── Paths ─────────────────────────────────────────────────────
set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%Invoke-STIGAssessment.ps1"
set "MODULES_DIR=%SCRIPT_DIR%modules"
set "REPORT_DIR=%SCRIPT_DIR%reports"
set "LOG_FILE=%REPORT_DIR%\assessment_log_%DATE:/=-%_%TIME::=-%_truncated.txt"

:: ── Sanity checks ─────────────────────────────────────────────
if not exist "%PS_SCRIPT%" (
    echo [ERROR] Cannot find: %PS_SCRIPT%
    echo         Ensure Invoke-STIGAssessment.ps1 is in the same directory.
    pause
    exit /b 1
)

if not exist "%MODULES_DIR%" (
    echo [WARNING] Modules directory not found: %MODULES_DIR%
    echo           Attempting to continue without modules...
)

if not exist "%REPORT_DIR%" (
    mkdir "%REPORT_DIR%" 2>nul
    echo [*] Created reports directory: %REPORT_DIR%
)

:: ── PowerShell version check ──────────────────────────────────
echo [*] Checking PowerShell version...
powershell -NoProfile -Command "$v = $PSVersionTable.PSVersion; if ($v.Major -lt 5) { Write-Error 'PowerShell 5.0+ required'; exit 1 } else { Write-Host ('[OK] PowerShell ' + $v.ToString()) }"
if %errorlevel% neq 0 (
    echo [ERROR] PowerShell 5.0 or later is required. Please upgrade.
    pause
    exit /b 1
)

:: ── SCAP / SCC check (optional, informational) ───────────────
echo [*] Checking for SCAP/SCC tools (optional)...
where scc.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] SCC tool detected. For full SCAP-based scanning, run SCC separately.
) else (
    echo [INFO] SCC tool not found. Running PowerShell-based checks only.
)

:: ── Launch assessment ─────────────────────────────────────────
echo.
echo ============================================================
echo   Starting STIG Assessment - %DATE% %TIME%
echo ============================================================
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
    -File "%PS_SCRIPT%" ^
    -OutputPath "%REPORT_DIR%" ^
    -ModulesPath "%MODULES_DIR%" ^
    -Format Both ^
    2>&1

set "PS_EXIT=%errorlevel%"

:: ── Result handling ───────────────────────────────────────────
echo.
if %PS_EXIT% equ 0 (
    echo [SUCCESS] Assessment completed. Reports saved to:
    echo           %REPORT_DIR%
    echo.
    echo Opening report directory...
    explorer "%REPORT_DIR%"
) else (
    echo [ERROR] Assessment exited with code %PS_EXIT%.
    echo         Check PowerShell output above for details.
    echo.
    echo Possible causes:
    echo   - Script execution policy not bypassed
    echo   - Missing module files in: %MODULES_DIR%
    echo   - Insufficient privileges for certain checks
    echo.
    echo Retry with verbose logging? [Y/N]
    set /p RETRY="> "
    if /i "!RETRY!"=="Y" (
        set "VLOG=%REPORT_DIR%\verbose_log.txt"
        echo [*] Verbose log will be saved to: !VLOG!
        echo.
        powershell.exe -NoProfile -ExecutionPolicy Bypass ^
            -File "%PS_SCRIPT%" ^
            -OutputPath "%REPORT_DIR%" ^
            -ModulesPath "%MODULES_DIR%" ^
            -Format Both ^
            -Verbose ^
            > "!VLOG!" 2>&1
        type "!VLOG!"
        echo.
        echo Verbose log saved to: %REPORT_DIR%\verbose_log.txt
    )
)

echo.
echo Press any key to exit...
pause >nul
endlocal
