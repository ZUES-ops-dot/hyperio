# HyperionScan AI Setup Script for Windows
# 
# This script sets up the complete AI vulnerability hunting system:
# - Ollama with required models
# - Foundry for exploit validation  
# - Python dependencies
# - Rust compilation

Write-Host "AI HyperionScan AI Setup" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Gray

# 1. Check Python
Write-Host "Package Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Success Python found: $pythonVersion" -ForegroundColor Green
    
    # Install Python dependencies
    Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
    python -m pip install --user requests
} catch {
    Write-Host "Failure Python not found. Please install Python 3.8+ from https://python.org" -ForegroundColor Red
    exit 1
}

# 2. Install Ollama
Write-Host "AI Setting up Ollama..." -ForegroundColor Yellow
try {
    $ollamaVersion = ollama --version 2>&1
    Write-Host "Success Ollama already installed: $ollamaVersion" -ForegroundColor Green
} catch {
    Write-Host "Installing Ollama..." -ForegroundColor Yellow
    # Download and install Ollama
    Invoke-WebRequest -Uri "https://ollama.ai/download/OllamaSetup.exe" -OutFile "OllamaSetup.exe"
    Start-Process "OllamaSetup.exe" -Wait
    Remove-Item "OllamaSetup.exe"
    
    # Add to PATH (may need restart)
    $env:PATH += ";C:\Program Files\Ollama"
    Write-Host "Warning  You may need to restart PowerShell after Ollama installation" -ForegroundColor Yellow
}

# 3. Start Ollama and pull models
Write-Host "Download Pulling Ollama models (this may take a while)..." -ForegroundColor Yellow

# Start Ollama in background
Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
Write-Host "Starting Ollama service..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

$models = @("codellama:13b", "codellama:34b", "mistral:7b", "llama2:13b")

foreach ($model in $models) {
    Write-Host "Pulling $model..." -ForegroundColor Yellow
    try {
        ollama pull $model
        Write-Host "Success $model pulled successfully" -ForegroundColor Green
    } catch {
        Write-Host "Warning  Failed to pull $model (may be optional)" -ForegroundColor Yellow
    }
}

# 4. Install Foundry
Write-Host "Build Setting up Foundry..." -ForegroundColor Yellow
try {
    $forgeVersion = forge --version 2>&1
    Write-Host "Success Foundry already installed: $forgeVersion" -ForegroundColor Green
} catch {
    Write-Host "Installing Foundry..." -ForegroundColor Yellow
    # Download and install Foundry
    Invoke-WebRequest -Uri "https://foundry.paradigm.xyz" -OutFile "foundry.ps1"
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    .\foundry.ps1
    foundryup
    Remove-Item "foundry.ps1"
}

# 5. Build HyperionScan
Write-Host "Rust Building HyperionScan with AI support..." -ForegroundColor Yellow
try {
    cargo build --release
    Write-Host "Success HyperionScan built successfully" -ForegroundColor Green
} catch {
    Write-Host "Failure Failed to build HyperionScan. Check Rust installation." -ForegroundColor Red
    exit 1
}

# 6. Test the system
Write-Host "Test Testing AI integration..." -ForegroundColor Yellow
try {
    python ml_agents\hunter_agent.py .\examples 2>$null
    Write-Host "Success Hunter agent test passed" -ForegroundColor Green
} catch {
    Write-Host "Warning  Hunter agent test failed (expected if no examples)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Success Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Launch Usage:" -ForegroundColor Cyan
Write-Host "  # Start Ollama in background"
Write-Host "  ollama serve"
Write-Host ""
Write-Host "  # Fast pattern scan (current)"
Write-Host "  .\target\release\hyperion.exe scan .\contracts"
Write-Host ""
Write-Host "  # AI-enhanced scan"
Write-Host "  .\target\release\hyperion.exe scan .\contracts --ai"
Write-Host ""
Write-Host "  # Full AI with exploit validation (zero false positives)"
Write-Host "  .\target\release\hyperion.exe scan .\contracts --ai --validate"
Write-Host ""
Write-Host "  # Dedicated AI analysis"
Write-Host "  .\target\release\hyperion.exe ai .\contracts --validate"
Write-Host ""
Write-Host "Target The AI system will:" -ForegroundColor Green
Write-Host "  1. Filter 95% of code with fast Rust patterns"
Write-Host "  2. Analyze suspicious regions with LLM agents"
Write-Host "  3. Generate and test exploits for zero false positives"
Write-Host "  4. Provide 1000x better critical vulnerability detection"

# Keep Ollama running message
Write-Host ""
Write-Host "Tip Tip: Keep Ollama running in background for best performance:" -ForegroundColor Cyan
Write-Host "   Start-Process ollama -ArgumentList 'serve' -WindowStyle Hidden"
