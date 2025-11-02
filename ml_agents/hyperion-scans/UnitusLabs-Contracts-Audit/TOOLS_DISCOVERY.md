# HyperionScan - Tools & Capabilities Discovery

## Overview

HyperionScan is a hybrid Rust/Python security scanner with AI-powered vulnerability detection for smart contracts.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HyperionScan Core (Rust)                 │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface  │  Pattern Engine  │  Report Generator      │
└────────┬────────┴────────┬─────────┴───────────┬────────────┘
         │                 │                     │
         ▼                 ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   ML Agents Layer (Python)                  │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Hunter Agent │ Knowledge    │ Embedding    │ Symbolic       │
│              │ Graph Engine │ Model        │ Execution      │
├──────────────┴──────────────┴──────────────┴────────────────┤
│                    Ollama LLM Integration                   │
│                      (Mistral 7B)                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Hunter Agent (`hunter_agent.py`)

**Purpose**: First-pass pattern detection and triage

**Capabilities**:
- Regex-based vulnerability pattern matching
- Suspicion scoring (0.0 - 1.0)
- Smart filtering to reduce LLM load

**Output**: Code regions ranked by suspicion score

---

### 2. Knowledge Graph Engine (`knowledge_graph.py`)

**Purpose**: Build semantic relationships between code entities

**Nodes**:
- Contracts
- Functions
- Variables
- External calls
- Events/Modifiers

**Edges**:
- CALLS (function → function)
- INHERITS (contract → contract)
- READS/WRITES (function → variable)
- EXTERNAL_CALL (function → external)

**Features**:
- Attack surface mapping
- Entry point identification
- Sensitive operation tracking
- O(n) optimized call graph building

---

### 3. Embedding Model (`embedding_model.py`)

**Purpose**: Code fingerprinting for vulnerability matching

**Embedding Components**:
- AST structural features
- Pattern fingerprints
- LLM text embeddings (optional)

**Vulnerability Signatures**:
```python
VULNERABILITY_SIGNATURES = {
    "classic_reentrancy": [...],
    "dangerous_delegatecall": [...],
    "tx_origin_auth": [...],
    "unchecked_send": [...],
    "integer_overflow": [...],
    "missing_access_control": [...]
}
```

---

### 4. Symbolic Execution Engine (`symbolic_execution.py`)

**Purpose**: Path-sensitive vulnerability detection

**Capabilities**:
- Taint tracking
- State transition analysis
- Access control verification
- Reentrancy detection (multiple patterns)
- Delegatecall trust analysis

**Critical Pattern Detection**:

| Pattern | Detection Method |
|---------|-----------------|
| REENTRANCY | External call → state change → no guard |
| REENTRANCY_LOOP | External call inside loop |
| ARBITRARY_DELEGATECALL | User-controlled target address |
| UNPROTECTED_SELFDESTRUCT | No access control |
| ARBITRARY_CALL | User controls target + data |
| MISSING_ACCESS_CONTROL | ETH transfer without auth |

---

### 5. Ollama LLM Integration (`ollama_client.py`)

**Purpose**: Deep semantic code understanding

**Features**:
- Auto-detect Mistral 7B model
- Multiple agent personalities (Hunter, Validator, Exploiter)
- Confidence scoring
- Timeout handling

**Agent Types**:
```python
class AgentType(Enum):
    HUNTER = "hunter"      # Find vulnerabilities
    VALIDATOR = "validator" # Verify findings
    EXPLOITER = "exploiter" # Generate PoCs
```

---

### 6. Exploit Generator (`exploit_generator.py`)

**Purpose**: Proof-of-Concept generation for confirmed vulnerabilities

**Templates**:
- Reentrancy exploit
- Access control bypass
- Integer overflow
- Flash loan attack

---

## Scripts

| Script | Purpose |
|--------|---------|
| `run_critical_scan.py` | Full symbolic scan, critical findings only |
| `analyze_critical.py` | Focused analysis on known vulnerable contracts |
| `run_quick_ai.py` | Quick test with LLM (5 files) |
| `run_full_ai_test.py` | Complete 6-stage pipeline |

---

## Performance Metrics

| Operation | Time | Files |
|-----------|------|-------|
| Symbolic scan | ~2s | 133 |
| Knowledge graph | ~30s | 133 |
| Focused analysis | 0.1s | 3 |
| LLM analysis | 80-120s | per region |

---

## Configuration

**Ollama URL**: `http://localhost:11434`

**Preferred Model**: `mistral:latest` (auto-detected)

**Analysis Thresholds**:
- Suspicion threshold: 0.5
- Confidence threshold: 0.7
- Max LLM regions: 50

---

## Future Improvements

1. **Slither/Mythril Integration** - Use proper Solidity AST parsing
2. **Foundry Test Generation** - Auto-generate exploit tests
3. **Cross-contract Analysis** - Track value flow across contracts
4. **CI/CD Integration** - GitHub Actions workflow
5. **Report Templates** - PDF/HTML export

---

*HyperionScan v0.1.0 - Built for Frontier*
