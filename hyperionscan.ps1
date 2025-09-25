<#
.SYNOPSIS
    HyperionScan - Local Security Scanner CLI
.DESCRIPTION
    PowerShell wrapper for the HyperionScan Rust engine.
#>

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
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Show-Banner {
    Write-ColorOutput @"

  _   _                      _             ____                  
 | | | |_   _ _ __   ___ _ __(_) ___  _ __ / ___|  ___ __ _ _ __  
 | |_| | | | | '_ \ / _ \ '__| |/ _ \| '_ \\___ \ / __/ _` | '_ \ 
 |  _  | |_| | |_) |  __/ |  | | (_) | | | |___) | (_| (_| | | | |
 |_| |_|\__, | .__/ \___|_|  |_|\___/|_| |_|____/ \___\__,_|_| |_|
        |___/|_|                                                  
                                                 
"@ "Cyan"
    Write-ColorOutput "  Local-Only Security Scanner v0.1.0" "Yellow"
    Write-ColorOutput "  ════════════════════════════════════════════════════════`n" "DarkGray"
}

function Show-Help {
    Show-Banner
    Write-ColorOutput "USAGE:" "Green"
    Write-Host "  .\hyperionscan.ps1 [command] [options]`n"

    Write-ColorOutput "COMMANDS:" "Green"
    Write-Host "  scan [target]     Scan a directory or Git repository"
    Write-Host "  plugins           List installed WASM plugins"
    Write-Host "  report            View last scan report (markdown)"
    Write-Host "  pdf               Export last scan as PDF"
    Write-Host "  findings          Show findings summary"
    Write-Host "  init              Create default configuration file"
    Write-Host "  build             Build the scanner from source"
    Write-Host "  version           Show version information"
    Write-Host "  help              Show this help message`n"

    Write-ColorOutput "OPTIONS:" "Green"
    Write-Host "  -Output <dir>     Output directory for reports (default: ./reports)"
    Write-Host "  -Format <types>   Report formats: json, markdown, pdf (default: json, markdown)"
    Write-Host "  -Fuzz             Enable fuzzing during scan"
    Write-Host "  -FuzzIterations   Number of fuzzing iterations (default: 100)"
    Write-Host "  -Severity <lvl>   Filter findings by severity (critical, high, medium, low)"
    Write-Host "  -Verbose          Enable verbose output`n"

    Write-ColorOutput "EXAMPLES:" "Green"
    Write-Host "  # Scan a local directory"
    Write-Host "  .\hyperionscan.ps1 scan C:\projects\my-contracts`n"

    Write-Host "  # Scan a GitHub repository"
    Write-Host "  .\hyperionscan.ps1 scan https://github.com/user/repo.git`n"

    Write-Host "  # Scan with fuzzing enabled"
    Write-Host "  .\hyperionscan.ps1 scan .\src -Fuzz -FuzzIterations 500`n"

    Write-Host "  # View critical findings only"
    Write-Host "  .\hyperionscan.ps1 findings -Severity critical`n"
}

function Start-Build {
    Write-ColorOutput "Build Building HyperionScan..." "Yellow"
    
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    Push-Location $scriptDir

    try {
        cargo build --release
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "Success Build successful!" "Green"
            Write-Host "Binary location: target\release\hyperion.exe"
        } else {
            Write-ColorOutput "Failure Build failed!" "Red"
            exit 1
        }
    } finally {
        Pop-Location
    }
}

function Invoke-Scan {
    param([string]$ScanTarget)

    if (-not $ScanTarget) {
        Write-ColorOutput "Failure Error: Target path or URL required" "Red"
        Write-Host "Usage: .\hyperionscan.ps1 scan [path|url]"
        exit 1
    }

    Show-Banner
    Write-ColorOutput "Inspect Starting scan..." "Yellow"
    Write-Host "Target: $ScanTarget"
    Write-Host "Output: $Output"
    Write-Host "Formats: $($Format -join ', ')`n"

    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $binary = Join-Path $scriptDir "target\release\hyperion.exe"
    
    # Check if binary exists, if not try cargo run
    if (-not (Test-Path $binary)) {
        Write-ColorOutput "Binary not found, using cargo run..." "DarkGray"
        $cmd = "cargo run --release --"
    } else {
        $cmd = $binary
    }

    $scanArgs = @("scan", $ScanTarget, "-o", $Output)
    
    foreach ($f in $Format) {
        $scanArgs += "-f"
        $scanArgs += $f
    }

    if ($Fuzz) {
        $scanArgs += "--fuzz"
        $scanArgs += "--fuzz-iterations"
        $scanArgs += $FuzzIterations
    }

    if ($VerboseOutput) {
        $scanArgs += "-v"
    }

    Push-Location $scriptDir
    try {
        if ($cmd -eq $binary) {
            & $binary $scanArgs
        } else {
            cargo run --release -- $scanArgs
        }
    } finally {
        Pop-Location
    }
}

function Show-Plugins {
    Show-Banner
    Write-ColorOutput "Package Installed Plugins:" "Yellow"
    
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $pluginsDir = Join-Path $scriptDir "plugins"

    if (Test-Path $pluginsDir) {
        $plugins = Get-ChildItem -Path $pluginsDir -Filter "*.wasm"
        
        if ($plugins.Count -eq 0) {
            Write-Host "  No plugins found in $pluginsDir"
            Write-Host "  Place .wasm plugin files in the plugins directory."
        } else {
            foreach ($plugin in $plugins) {
                $name = [System.IO.Path]::GetFileNameWithoutExtension($plugin.Name)
                $size = "{0:N2} KB" -f ($plugin.Length / 1KB)
                Write-Host "  - $name ($size)"
            }
        }
    } else {
        Write-Host "  Plugins directory not found: $pluginsDir"
        Write-Host "  Creating directory..."
        New-Item -ItemType Directory -Path $pluginsDir -Force | Out-Null
    }
}

function Show-Report {
    $reportPath = Join-Path $Output "last_scan.md"
    
    if (Test-Path $reportPath) {
        Get-Content $reportPath
    } else {
        Write-ColorOutput "Failure No report found at $reportPath" "Red"
        Write-Host "Run a scan first: .\hyperionscan.ps1 scan [target]"
    }
}

function Export-Pdf {
    Show-Banner
    $jsonPath = Join-Path $Output "last_scan.json"
    
    if (-not (Test-Path $jsonPath)) {
        Write-ColorOutput "Failure No scan results found" "Red"
        Write-Host "Run a scan first: .\hyperionscan.ps1 scan [target]"
        return
    }

    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    Push-Location $scriptDir
    try {
        cargo run --release -- pdf -d $Output
    } finally {
        Pop-Location
    }
}

function Show-Findings {
    Show-Banner
    $jsonPath = Join-Path $Output "last_scan.json"
    
    if (-not (Test-Path $jsonPath)) {
        Write-ColorOutput "Failure No scan results found" "Red"
        Write-Host "Run a scan first: .\hyperionscan.ps1 scan [target]"
        return
    }

    $results = Get-Content $jsonPath | ConvertFrom-Json
    
    Write-ColorOutput "Checklist Scan Findings Summary`n" "Yellow"
    Write-Host "═══════════════════════════════════════════════════════════`n"

    $findings = $results.findings
    
    if ($Severity) {
        $findings = $findings | Where-Object { $_.severity -eq $Severity }
    }

    foreach ($finding in $findings) {
        $icon = switch ($finding.severity) {
            "critical" { "Critical" }
            "high" { "High" }
            "medium" { "Medium" }
            "low" { "Low" }
            default { "Info" }
        }

        $color = switch ($finding.severity) {
            "critical" { "Red" }
            "high" { "DarkYellow" }
            "medium" { "Yellow" }
            "low" { "Green" }
            default { "Gray" }
        }

        Write-ColorOutput "$icon [$($finding.severity.ToUpper())] $($finding.id)" $color
        Write-Host "   File: $($finding.path):$($finding.line)"
        Write-Host "   $($finding.message)`n"
    }

    # Summary
    $critical = ($results.findings | Where-Object { $_.severity -eq "critical" }).Count
    $high = ($results.findings | Where-Object { $_.severity -eq "high" }).Count
    $medium = ($results.findings | Where-Object { $_.severity -eq "medium" }).Count
    $low = ($results.findings | Where-Object { $_.severity -eq "low" }).Count

    Write-Host "═══════════════════════════════════════════════════════════"
    Write-ColorOutput "Summary: $critical Critical, $high High, $medium Medium, $low Low" "Cyan"
}

function Initialize-Config {
    Show-Banner
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    
    Push-Location $scriptDir
    try {
        cargo run --release -- init
    } finally {
        Pop-Location
    }
}

function Show-Version {
    Show-Banner
    Write-Host "HyperionScan v0.1.0"
    Write-Host "Rust Core Engine with WASM Plugin Support"
    Write-Host ""
    Write-Host "Components:"
    Write-Host "  - File Walker (walkdir)"
    Write-Host "  - AST Parser (tree-sitter)"
    Write-Host "  - Plugin Loader (wasmtime)"
    Write-Host "  - Report Generator (JSON/MD/PDF)"
}

# Main execution
switch ($Command) {
    "scan" { Invoke-Scan -ScanTarget $Target }
    "plugins" { Show-Plugins }
    "report" { Show-Report }
    "pdf" { Export-Pdf }
    "findings" { Show-Findings }
    "init" { Initialize-Config }
    "build" { Start-Build }
    "version" { Show-Version }
    "help" { Show-Help }
    default { Show-Help }
}
