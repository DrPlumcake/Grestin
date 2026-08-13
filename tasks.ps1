<#
.SYNOPSIS
    Task runner for the grestin project on Windows / PowerShell.

.DESCRIPTION
    Replaces the Unix Makefile. Run from the repository root.

    If PowerShell refuses to run this file ("running scripts is disabled on
    this system"), allow local scripts once, for your user only:

        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

.EXAMPLE
    .\tasks.ps1 install
    .\tasks.ps1 test
    .\tasks.ps1 demo
    .\tasks.ps1 fixtool -Tool "C:\path\to\Third Parties Risk Evaluation Tool v2.0.xlsx"
    .\tasks.ps1 run -Target config\targets_example.yaml -Tool "C:\path\to\tool_lo.xlsx"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'test', 'lint', 'guard', 'coverage', 'demo', 'run', 'fixtool', 'clean', 'help')]
    [string]$Task = 'help',

    [string]$Target = 'config\targets_example.yaml',
    [string]$Tool = '',
    [string]$RunId = 'DEMO',
    [switch]$Offline,
    [switch]$WriteAnswers
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Assert-Venv {
    if (-not $env:VIRTUAL_ENV) {
        Write-Warning "No virtual environment active. Activate it first:`n    .\.venv\Scripts\Activate.ps1"
    }
}

switch ($Task) {

    'install' {
        if (-not (Test-Path '.venv')) { python -m venv .venv }
        & .\.venv\Scripts\python.exe -m pip install --upgrade pip
        & .\.venv\Scripts\python.exe -m pip install -e '.[dev]'
        if (-not (Test-Path '.env')) { Copy-Item '.env.example' '.env' }
        Write-Host "`nDone. Activate the environment with:  .\.venv\Scripts\Activate.ps1" -ForegroundColor Green
    }

    'test' {
        Assert-Venv
        # The prefill tests skip unless this points at the Excel tool.
        if ($Tool) { $env:TPRM_TOOL_XLSX = $Tool }
        pytest -q
    }

    'lint'     { Assert-Venv; ruff check src tests tools }

    'guard' {
        Assert-Venv
        Write-Host "`n--- must be BLOCKED ---" -ForegroundColor Yellow
        grestin guard --url "https://api.shodan.io/shodan/scan?ips=1.2.3.4"
        Write-Host "`n--- must be ALLOWED ---" -ForegroundColor Yellow
        grestin guard --url "https://crt.sh/?q=example.com"
    }

    'coverage' { Assert-Venv; grestin coverage }

    'demo' {
        Assert-Venv
        python tools\seed_demo_evidence.py $RunId
        grestin run --target config\targets_example.yaml --offline --run-id $RunId
    }

    'run' {
        Assert-Venv
        $cliArgs = @('run', '--target', $Target)
        if ($Offline)      { $cliArgs += @('--offline', '--run-id', $RunId) }
        if ($Tool)         { $cliArgs += @('--prefill', $Tool) }
        if ($WriteAnswers) { $cliArgs += '--write-answers' }
        grestin @cliArgs
    }

    'fixtool' {
        Assert-Venv
        if (-not $Tool) { throw "Pass the workbook: .\tasks.ps1 fixtool -Tool 'C:\path\tool.xlsx'" }
        python tools\make_libreoffice_safe.py $Tool
    }

    'clean' {
        Get-ChildItem -Path . -Include '__pycache__', '.pytest_cache', '.ruff_cache' -Recurse -Directory |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path 'out', 'evidence' -Exclude '.gitkeep' -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force
        Write-Host 'Cleaned.' -ForegroundColor Green
    }

    default {
        Get-Help $PSCommandPath -Detailed
    }
}
