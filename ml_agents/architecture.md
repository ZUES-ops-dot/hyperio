# HyperionScan AI Agent Architecture

## AI Multi-Agent Organism Design

### Core Concept
Transform HyperionScan from pattern-based scanner to **autonomous vulnerability hunting organism** using local Ollama LLMs.

### Agent Specializations

#### 1. **Hunter Agent** - Pattern Discovery
- Uses current Rust scanner for fast initial triage
- Identifies "interesting code regions" (high suspicion)
- Feeds only 5-10% of code to expensive LLM analysis
- Focus: `external calls`, `state changes`, `access control`

#### 2. **Taint Tracer Agent** - Dataflow Analysis
- Tracks user input through contract execution
- Identifies where external parameters affect critical state
- Uses tree-sitter AST + symbolic execution hints
- Focus: `msg.sender`, `msg.value`, function parameters

#### 3. **Cross-Contract Agent** - Interaction Modeling
- Builds call graphs across all contracts
- Models attack vectors through multiple contracts
- Detects reentrancy, delegatecall risks
- Focus: `call()`, `delegatecall()`, `staticcall()`

#### 4. **Exploit Generator Agent** - PoC Creation
- Generates actual Foundry/Hardhat exploit code
- Auto-runs exploits against contract bytecode
- Only reports SUCCESSFUL exploits (0% false positives)
- Focus: Real attack validation

#### 5. **Synthesizer Agent** - Intelligence Fusion
- Combines findings from all agents
- Ranks by exploitability and impact
- Generates contextual remediation
- Focus: Final vulnerability intelligence

### Data Flow

```
1. Hunter Agent (Rust) → Interesting Regions (5% of code)
2. Parallel Agents (Ollama) → Deep Analysis
3. Exploit Generator → Validation Tests
4. Synthesizer → Final Report (100% accurate)
```

### Ollama Integration

```python
# Local models for each agent
MODELS = {
    "hunter": "codellama:13b",      # Fast code analysis
    "taint": "codellama:34b",       # Complex reasoning  
    "cross": "mistral:7b",          # Graph analysis
    "exploit": "codellama:34b",     # Code generation
    "synth": "llama2:70b",          # Final synthesis
}
```

### Performance Targets

| Metric | Current | Target AI |
|--------|---------|-----------|
| False Positives | 40% | **0%** (exploit validated) |
| Critical Detection | 60% | **95%** (semantic understanding) |
| Scan Time | 10s | 60s (but 1000x more accurate) |
| Coverage | Lines of Code | **Attack Surface** (semantic) |

---

## Implementation Plan

### Phase 1: Hunter Agent Enhancement
- Extend current scanner to tag "suspicious regions"
- Add scoring system for LLM triage
- Implement Python bridge to Ollama

### Phase 2: Taint Tracer Agent  
- Build dataflow analysis with tree-sitter
- Create Ollama prompts for taint analysis
- Validate with known vulnerabilities

### Phase 3: Cross-Contract Agent
- Parse entire codebase into call graph
- Model multi-contract attack vectors
- Detect complex reentrancy patterns

### Phase 4: Exploit Generator
- Auto-generate Foundry test files
- Compile and run exploits automatically
- Only report successful exploitations

### Phase 5: Synthesizer Intelligence
- Fuse all agent findings
- Generate contextual remediation
- Create attack scenario documentation

---

## The "Organism" Effect

This system behaves like a predator:
1. **Senses** environment (Hunter Agent)
2. **Tracks** movement (Taint Tracer)  
3. **Understands** relationships (Cross-Contract)
4. **Tests** attacks (Exploit Generator)
5. **Learns** and adapts (Synthesizer)

**Result**: 1000x better critical vulnerability detection with zero false positives.
