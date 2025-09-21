# HyperionScan

![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Status: Beta](https://img.shields.io/badge/status-beta-blue)

> HyperionScan is a local-first smart contract and polyglot code security scanner with WASM plugin isolation, AI-assisted auditing, and artifact-quality reporting.

## Table of Contents

1. [Why HyperionScan](#why-hyperionscan)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [AI-Powered Vulnerability Hunting](#ai-powered-vulnerability-hunting)
7. [Configuration](#configuration)
8. [Repository Layout](#repository-layout)
9. [Development](#development)
10. [Contributing & Support](#contributing--support)
11. [License](#license)

## Why HyperionScan

- **100% Local** – Runs entirely on your machine. No outbound calls, no code exfiltration.
- **Composable WASM Plugins** – Sandbox risky analysis logic and ship plugins independently.
- **Precise AST Analysis** – Tree-sitter powered parsing for Solidity, Rust, Move, Vyper, Cairo, JavaScript, and TypeScript.
- **Artifact-Ready Reports** – JSON, Markdown, and PDF output with optional snippets and severity triage.
- **Built-In Fuzzing** – Toggle deterministic fuzzing per target with iteration and timeout controls.
- **Optional ML & LLM Agents** – Blend heuristic detection with AI triage for critical findings.

## Architecture

```
┌──────────────────────────────┐
│      PowerShell Wrapper      │
│        hyperionscan.ps1      │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│        Rust Core Engine (CLI App)        │
│------------------------------------------│
│  • Repo Cloner (git2)                    │
│  • File Walker (walkdir/glob)            │
│  • Language Detector + AST (tree-sitter) │
│  • Plugin Host (WASM + CLI adapters)     │
│  • Fuzzing + ML Modules                  │
│  • Report Pipeline (JSON/MD/PDF)         │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────┐
│        Plugin Ecosystem      │
│------------------------------│
│ - solidity_scanner           │
│ - rust_scanner               │
│ - secret_scanner             │
│ - pattern_scanner            │
└──────────────────────────────┘
```

## Requirements

- Rust 1.74+ with the 2021 edition toolchain
- Python 3.8+ (AI/ML workflows)
- Node.js 18+ (optional plugin development)
- PowerShell 7+ on Windows or any POSIX-friendly shell for `setup_ai.sh`
- Optional: [Ollama](https://ollama.com) for on-device LLMs and [Foundry](https://book.getfoundry.sh/) for exploit validation

## Installation

### Windows (PowerShell)

```powershell
# Install Rust toolchain first: https://rustup.rs
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
./setup_ai.ps1            # Installs Python deps, Ollama, Foundry, builds binaries
```

### Linux / macOS (Bash)

```bash
curl https://sh.rustup.rs -sSf | sh      # If Rust is not installed yet
chmod +x setup_ai.sh
./setup_ai.sh
```

The scripts build `hyperion` in release mode and validate the AI agents. You can always rebuild manually with `cargo build --release`.

## Quick Start

### PowerShell Wrapper

```powershell
# Scan a local directory
.\hyperionscan.ps1 scan "C:\projects\my-contracts"

# Scan a Git repository
.\hyperionscan.ps1 scan "https://github.com/user/repo.git"

# List installed plugins
.\hyperionscan.ps1 plugins

# View previous findings
.\hyperionscan.ps1 report --format markdown
```

### Cargo CLI

```bash
cargo build --release

# Baseline scan
./target/release/hyperion scan ./my-project

# Enable fuzzing & AI agents
./target/release/hyperion scan ./my-project --fuzz --ai --validate

# Run the dedicated AI mode
./target/release/hyperion ai ./contracts --threshold 0.6 --max-regions 75
```

## AI-Powered Vulnerability Hunting

HyperionScan includes a multi-stage AI pipeline for high-signal findings:

| Stage | Component | Description |
|-------|-----------|-------------|
| 1 | **Hunter Agent** | Fast Rust heuristics filter ~95 % of noise |
| 2 | **Knowledge Graph** | Builds semantic views & attack surfaces |
| 3 | **Embedding Model** | Performs similarity search on code fingerprints |
| 4 | **Symbolic Execution** | Path-sensitive reasoning & taint tracking |
| 5 | **LLM Agents (Ollama)** | Deep semantic analysis (Mistral 7B / CodeLlama) |
| 6 | **Exploit Generator (Foundry)** | Auto-generates PoC tests for zero false positives |

**AI Quick Start**

```powershell
ollama serve
.\hyperionscan.ps1 scan ".\contracts" --ai --validate
.\hyperionscan.ps1 ai ".\contracts" --threshold 0.5
```

### Common Findings

- Classic and cross-function reentrancy
- Dangerous `delegatecall` or upgradeable gaps
- `tx.origin` authentication misuse
- Missing access controls on privileged functions
- Unchecked return values and external call failures

## Configuration

Create `hyperion.toml` (sample provided at repo root):

```toml
[scan]
exclude = ["node_modules", "target", ".git"]
languages = ["solidity", "rust", "move"]
max_file_size = 10_485_760
follow_symlinks = false

[plugins]
dir = "./plugins"
enabled = ["solidity_scanner", "secret_scanner", "pattern_scanner"]
timeout_seconds = 30
max_memory_mb = 256

[report]
formats = ["json", "markdown"]
output_dir = "./reports"
include_snippets = true
snippet_lines = 5

[fuzzing]
enabled = false
iterations = 1000
timeout_seconds = 60

[ml]
enabled = false
threshold = 0.7
```

## Repository Layout

| Path | Description |
|------|-------------|
| `src/` | Rust core engine, CLI entry point, config, AI bridge, reporting |
| `plugins/` | WASM and CLI plugin sources plus manifests |
| `ml_agents/` | Python orchestrators, hunter agent, and AI utilities |
| `examples/` | Sample targets and demo scan inputs |
| `test-contracts/` | Solidity fixtures used in regression tests |
| `tests/` | Integration and smoke tests |
| `hyperionscan.ps1` / `scan.ps1` | Windows-first orchestration scripts |
| `setup_ai.sh` / `setup_ai.ps1` | Automated bootstrap for AI/Foundry/Ollama stack |
| `reports/` | Generated findings (gitignored) |

## Development

```bash
# Run fmt & tests
cargo fmt
cargo clippy --all-targets --all-features
cargo test

# Lint Python agents
ruff check ml_agents
pytest tests
```

Additional ideas and roadmap notes live in [`HYPERION_IMPROVEMENTS.md`](HYPERION_IMPROVEMENTS.md).

## Contributing & Support

- Read the [Contribution Guide](CONTRIBUTING.md) before opening issues or PRs.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Report security-sensitive issues via [SECURITY.md](SECURITY.md).

## License

HyperionScan is distributed under the [MIT License](LICENSE).
