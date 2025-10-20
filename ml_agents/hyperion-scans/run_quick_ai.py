#!/usr/bin/env python3
"""Quick HyperionAI test on limited files"""
import time
from pathlib import Path

print("=" * 60)
print("AI HYPERION AI - QUICK TEST")
print("=" * 60)

start = time.time()

# Test just a few files
test_dir = Path("../test-contracts/src")
test_files = list(test_dir.glob("*.sol"))[:5]  # Only top-level files

print(f"\nFolder Testing {len(test_files)} files")
for f in test_files:
    print(f"   • {f.name}")

# Stage 1: Hunter
print("\nTarget Stage 1: Hunter Agent")
from hunter_agent import HunterAgent
hunter = HunterAgent()
regions = []
for f in test_files:
    regions.extend(hunter.scan_file(f))
high = hunter.triage_for_llm(regions, 0.5)
print(f"   Regions: {len(regions)} → {len(high)} suspicious")

# Stage 2: Embeddings (fast)
print("\nStep Stage 2: Embeddings")
from embedding_model import EmbeddingModel
em = EmbeddingModel()
embeddings = []
for f in test_files:
    code = f.read_text(encoding='utf-8', errors='ignore')
    emb = em.embed_code(code, str(f), 1, 100, use_llm=False)
    embeddings.append(emb)
    if emb.vulnerability_type:
        print(f"   {f.name}: {emb.vulnerability_type} (conf: {emb.confidence:.2f})")

# Stage 3: Symbolic
print("\nFast Stage 3: Symbolic Execution")
from symbolic_execution import SymbolicExecutionEngine
se = SymbolicExecutionEngine()
all_violations = []
for f in test_files:
    v = se.analyze_file(f)
    all_violations.extend(v)
critical = [v for v in all_violations if v.severity == 'critical']
print(f"   Critical: {len(critical)}, High: {len(all_violations) - len(critical)}")
for v in critical:
    print(f"   Critical {v.violation_type}: {Path(v.file_path).name}:{v.line_number}")

# Stage 4: LLM
print("\nAI Stage 4: LLM (Mistral)")
from ollama_client import OllamaClient, LLMRequest, AgentType
client = OllamaClient()

if client.check_connection() and high:
    print(f"   Model: {client.default_model}")
    region = high[0]
    req = LLMRequest(
        agent=AgentType.HUNTER,
        prompt=f"List vulnerabilities in this Solidity:\n{region.content[:1000]}",
        context={}
    )
    resp = client.generate(req)
    print(f"   Time: {resp.processing_time:.1f}s")
    print(f"   Confidence: {resp.confidence}")
    print(f"   Response: {resp.response[:300]}...")
else:
    print("   Warning Ollama not available or no suspicious code")

# Summary
print(f"\n{'='*60}")
print(f"Success Complete in {time.time()-start:.1f}s")
print(f"   Critical: {len(critical)}")
print(f"   Suspicious regions: {len(high)}")
print(f"{'='*60}")
