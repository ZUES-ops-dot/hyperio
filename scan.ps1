# HyperionScan - PowerShell CLI Wrapper
# Simple wrapper for the Rust binary

param(
    [Parameter(Position=0)]
    [string]$Command = "help",
    
    [Parameter(Position=1)]
    [string]$Target,
    
    [string]$Output = "./reports",
    [string[]]$Format = @("json", "markdown"),
    [switch]$Fuzz,
    [int]$FuzzIterations = 100,
    [string]$Severity,
    [switch]$V
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binary = Join-Path $scriptDir "target\release\hyperion.exe"

function Show-Help {
    Write-Host ""
    Write-Host "HyperionScan - Local Security Scanner" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Green
    Write-Host "  .\scan.ps1 [command] [options]"
    Write-Host ""
    Write-Host "COMMANDS:" -ForegroundColor Green
    Write-Host "  scan [path]    Scan a directory or Git repository"
    Write-Host "  plugins        List installed plugins"
    Write-Host "  report         View last scan report"
    Write-Host "  findings       Show findings summary"
    Write-Host "  pdf            Export as PDF"
    Write-Host "  build          Build from source"
    Write-Host "  help           Show this help"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Green
    Write-Host "  .\scan.ps1 scan .\examples"
    Write-Host "  .\scan.ps1 scan C:\projects\contracts -Fuzz"
    Write-Host "  .\scan.ps1 findings -Severity high"
    Write-Host ""
}

function Get-Binary {
    if (Test-Path $binary) {
        return $binary
    }
    Write-Host "Binary not found. Building..." -ForegroundColor Yellow
    Push-Location $scriptDir
    cargo build --release
    Pop-Location
    return $binary
}

function Invoke-HyperionCommand {
    param([string[]]$Arguments)
    
    $bin = Get-Binary
    if (-not (Test-Path $bin)) {
        Write-Host "ERROR: Failed to build binary" -ForegroundColor Red
        exit 1
    }
    
    & $bin $Arguments
}

switch ($Command.ToLower()) {
    "help" {
        Show-Help
    }
    "scan" {
        if (-not $Target) {
            Write-Host "ERROR: Target path required" -ForegroundColor Red
            Write-Host "Usage: .\scan.ps1 scan [path]"
            exit 1
        }
        
        $cmdArgs = @("scan", $Target, "-o", $Output)
        foreach ($f in $Format) {
            $cmdArgs += @("-f", $f)
        }
        if ($Fuzz) {
            $cmdArgs += @("--fuzz", "--fuzz-iterations", $FuzzIterations)
        }
        if ($V) {
            $cmdArgs += "-v"
        }
        
        Invoke-HyperionCommand $cmdArgs
    }
    "plugins" {
        Invoke-HyperionCommand @("plugins", "-d", "./plugins")
    }
    "report" {
        Invoke-HyperionCommand @("report", "-d", $Output)
    }
    "findings" {
        $cmdArgs = @("findings", "-d", $Output)
        if ($Severity) {
            $cmdArgs += @("-s", $Severity)
        }
        Invoke-HyperionCommand $cmdArgs
    }
    "pdf" {
        Invoke-HyperionCommand @("pdf", "-d", $Output)
    }
    "build" {
        Write-Host "Building HyperionScan..." -ForegroundColor Yellow
        Push-Location $scriptDir
        cargo build --release
        Pop-Location
        Write-Host "Build complete!" -ForegroundColor Green
    }
    default {
        Write-Host "Unknown command: $Command" -ForegroundColor Red
        Show-Help
    }
}
