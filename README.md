# HyperionScan -- Local-First Smart Contract Security Scanner

![Rust](https://img.shields.io/badge/Rust-1.75+-orange?logo=rust&logoColor=white)
![tree-sitter](https://img.shields.io/badge/Tree--sitter-AST-FFCA28)
![WASM](https://img.shields.io/badge/WASM-plugins-654FF0?logo=webassembly)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-blue)

> Local-first polyglot code scanner with WASM-isolated plugins, AST-precise vulnerability detection across 7 languages, deterministic fuzzing, and optional LLM triage. **Your code never leaves your machine.**

**[Architecture](#architecture)** · **[Quick Start](#quick-start)** · **[Plugin SDK](#plugins)**

---

## What problem this solves

Cloud-hosted security scanners (Snyk, Mythril, Slither) require uploading source. For audit work on private contracts and pre-IPO code, that's a non-starter. HyperionScan runs entirely on your machine, isolates risky analysis logic in WASM sandboxes, and produces audit-quality JSON / Markdown / PDF reports.

**Built for:**
- Audit firms reviewing pre-disclosure contracts
- Internal security teams that can't ship code outside the network
- Devs who want fast feedback in their editor without cloud round-trips

## Highlights

- **100% local** -- no outbound network calls, no telemetry, no code exfiltration
- **Composable WASM plugins** -- sandboxed plugin runtime via `wasmtime`; ship custom rules without recompiling the host
- **tree-sitter AST analysis** -- precise parsing for **Solidity, Rust, Move, Vyper, Cairo, JavaScript, TypeScript**
- **Built-in fuzzing** -- deterministic per-target fuzzer with iteration + timeout controls
- **Artifact-quality reports** -- JSON for CI pipelines, Markdown for PRs, PDF for client deliverables; severity triage + snippet excerpts
- **Optional ML / LLM agents** -- heuristic detection blended with AI triage on critical findings (opt-in, still local: Ollama + local model)

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  CLI / file watcher / GitHub Action                               │
└──────────────────────────┬───────────────────────────────────────┘
                           ▼
                ┌──────────────────────┐
                │  Scanner core        │
                │  (Rust)              │
                └──────┬───────────────┘
                       │
   ┌───────────────────┼───────────────────┐
   ▼                   ▼                   ▼
┌──────────┐  ┌──────────────────┐  ┌────────────────┐
│ Parsers  │  │ Heuristic rules  │  │ Plugin host    │
│ (TS)     │  │ (built-in)       │  │ (wasmtime)     │
│ Solidity │  │ • reentrancy     │  │ ┌────────────┐ │
│ Rust     │  │ • int overflow   │  │ │  WASM      │ │
│ Move     │  │ • secrets        │  │ │  plugin    │ │
│ Vyper    │  │ • tx-origin      │  │ │  sandbox   │ │
│ Cairo    │  │ • unchecked call │  │ └────────────┘ │
│ JS/TS    │  └──────────────────┘  └────────────────┘
└──────────┘                                │
                                            ▼
                              ┌──────────────────────┐
                              │ Optional ML / LLM    │
                              │ agent (local Ollama) │
                              │ -- triages criticals  │
                              └──────────┬───────────┘
                                         ▼
                              ┌──────────────────────┐
                              │ Report writer        │
                              │ JSON / MD / PDF      │
                              └──────────────────────┘
```

## Tech stack

| Layer | Tech |
|-------|------|
| Core | Rust (2021 edition), `tokio` runtime |
| Parsing | tree-sitter grammars per language |
| Plugins | `wasmtime` WASM sandbox |
| ML | `candle` for local inference (optional) |
| LLM | Ollama integration (optional) |
| CLI | `clap` v4 |
| Reports | `serde_json`, `pulldown-cmark`, `printpdf` |
| Fuzzing | Deterministic seedable fuzzer |

## Quick Start

```bash
git clone https://github.com/ZUES-ops-dot/hyperio.git
cd hyperio
cargo build --release

# Scan a directory
./target/release/hyperio scan ./contracts

# JSON report
./target/release/hyperio scan ./contracts --format json --out report.json

# With AI triage on critical findings (requires Ollama)
./target/release/hyperio scan ./contracts --ai-triage
```

### As a library

```toml
[dependencies]
hyperio = { git = "https://github.com/ZUES-ops-dot/hyperio" }
```

```rust
use hyperio::Scanner;

let findings = Scanner::new()
    .with_plugin("./plugins/reentrancy.wasm")
    .scan_path("./contracts")?;

for f in findings.iter().filter(|f| f.severity >= Severity::High) {
    println!("{}", f);
}
```

## Plugins

Plugins are WASM modules that implement a small ABI and run sandboxed:

```rust
// plugins/my_rule/src/lib.rs
#[no_mangle]
pub extern "C" fn analyze(ast_ptr: *const u8, len: usize) -> *mut Findings {
    // ...
}
```

Build and load:

```bash
cd plugins/my_rule
cargo build --target wasm32-unknown-unknown --release
hyperio scan ./contracts --plugin ./target/wasm32-unknown-unknown/release/my_rule.wasm
```

See `plugins/secret_scanner/` for a complete example covering API key, AWS, Stripe, and private-key heuristics.

## Repository layout

```
src/
  scanner/        Core scanner pipeline
  ai/             Optional ML + LLM triage
  reports/        JSON / Markdown / PDF writers
  core/           Findings model, severity, AST helpers
  plugins/        Plugin host (wasmtime)
plugins/
  secret_scanner/ Reference WASM plugin
ml_agents/        Optional local triage models
examples/         Vulnerable sample contracts
tests/            Integration tests with fixture inputs
```

## Roadmap

See [Issues](https://github.com/ZUES-ops-dot/hyperio/issues) -- WASM browser build, parallelized traversal with `rayon`, GitHub Action wrapper, false-positive reduction on `*_KEY_ID`-style env vars.

## License

MIT -- see [LICENSE](LICENSE).
