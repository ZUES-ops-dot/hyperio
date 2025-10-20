#!/usr/bin/env python3
"""
Full HyperionScan analysis of CratD2C repository
"""
import json
import time
from pathlib import Path
from collections import defaultdict, Counter

TARGET_DIR = Path("../CratD2C-contracts/contracts")
REPO_URL = "https://github.com/samaros/CratD2C"

def main():
    print("=" * 60)
    print("AI HYPERION AI - CratD2C AUDIT")
    print(f"Package Repository: {REPO_URL}")
    print("=" * 60)
    
    start_time = time.time()
    
    # Find all Solidity files
    sol_files = list(TARGET_DIR.rglob("*.sol"))
    print(f"\nFolder Found {len(sol_files)} Solidity files:")
    for f in sol_files:
        print(f"   • {f.relative_to(TARGET_DIR)}")
    
    # =========================================================
    # Stage 1: Hunter Agent
    # =========================================================
    print(f"\nTarget Stage 1: Hunter Agent - Pattern Triage")
    print("-" * 40)
    from hunter_agent import HunterAgent
    hunter = HunterAgent()
    all_regions = hunter.scan_directory(TARGET_DIR)
    high_suspicion = hunter.triage_for_llm(all_regions, threshold=0.5)
    print(f"   Total regions: {len(all_regions)}")
    print(f"   High suspicion: {len(high_suspicion)}")
    
    # =========================================================
    # Stage 2: Knowledge Graph
    # =========================================================
    print(f"\nChart Stage 2: Knowledge Graph")
    print("-" * 40)
    from knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.build_from_directory(TARGET_DIR, verbose=True)
    
    # =========================================================
    # Stage 3: Embeddings
    # =========================================================
    print(f"\nStep Stage 3: Embedding Model")
    print("-" * 40)
    from embedding_model import EmbeddingModel
    em = EmbeddingModel()
    embeddings = em.embed_directory(TARGET_DIR, use_llm=False)
    clusters = em.cluster_by_vulnerability(embeddings)
    print(f"   Embeddings: {len(embeddings)}")
    for vtype, embs in clusters.items():
        if vtype != "unknown" and len(embs) > 0:
            print(f"   {vtype}: {len(embs)} matches")
    
    # =========================================================
    # Stage 4: Symbolic Execution
    # =========================================================
    print(f"\nFast Stage 4: Symbolic Execution - Critical Scan")
    print("-" * 40)
    from symbolic_execution import SymbolicExecutionEngine
    se = SymbolicExecutionEngine()
    sym_results = se.analyze_directory(TARGET_DIR)
    
    # Filter mocks
    all_violations = [
        v for v in sym_results['violations']
        if 'mock' not in v['file_path'].lower()
    ]
    
    critical = [v for v in all_violations if v['severity'] == 'critical']
    high = [v for v in all_violations if v['severity'] == 'high']
    
    print(f"\n   Results (excluding mocks):")
    print(f"   Critical Critical: {len(critical)}")
    print(f"   High High: {len(high)}")
    
    # =========================================================
    # Stage 5: LLM Analysis (if available)
    # =========================================================
    print(f"\nAI Stage 5: LLM Analysis (Mistral)")
    print("-" * 40)
    from ollama_client import OllamaClient, LLMRequest, AgentType
    client = OllamaClient()
    
    llm_analysis = None
    if client.check_connection() and high_suspicion:
        print(f"   Success Connected: {client.default_model}")
        # Analyze most suspicious region
        region = high_suspicion[0]
        req = LLMRequest(
            agent=AgentType.HUNTER,
            prompt=f"Analyze for vulnerabilities:\n{region.content[:1500]}",
            context={"file": region.file_path}
        )
        resp = client.generate(req)
        print(f"   Response time: {resp.processing_time:.1f}s")
        llm_analysis = resp.response[:500]
    else:
        print("   Warning Ollama not available")
    
    # =========================================================
    # Print Findings
    # =========================================================
    print(f"\n{'='*60}")
    print("Critical CRITICAL FINDINGS")
    print(f"{'='*60}")
    
    for v in critical:
        print(f"\n[{v['violation_type']}] {Path(v['file_path']).name}:{v['line_number']}")
        print(f"   {v['description']}")
        if v.get('exploit_conditions'):
            print(f"   Exploit: {v['exploit_conditions'][0]}")
    
    if not critical:
        print("\n   No critical vulnerabilities found!")
    
    print(f"\n{'='*60}")
    print("High HIGH SEVERITY FINDINGS")
    print(f"{'='*60}")
    
    by_type = Counter(v['violation_type'] for v in high)
    for vtype, count in by_type.items():
        print(f"   {vtype}: {count}")
    
    # =========================================================
    # Generate Report
    # =========================================================
    total_time = time.time() - start_time
    
    report = {
        "repository": REPO_URL,
        "audit_date": "2025-11-28",
        "scanner": "HyperionScan",
        "analysis_time_seconds": total_time,
        "summary": {
            "total_files": len(sol_files),
            "total_functions": len(kg.functions),
            "total_variables": len(kg.variables),
            "critical_count": len(critical),
            "high_count": len(high),
            "knowledge_graph_nodes": len(kg.nodes),
            "knowledge_graph_edges": len(kg.edges)
        },
        "critical_vulnerabilities": [
            {
                "type": v['violation_type'],
                "severity": v['severity'],
                "file": Path(v['file_path']).name,
                "line": v['line_number'],
                "description": v['description'],
                "exploit_conditions": v.get('exploit_conditions', [])
            }
            for v in critical
        ],
        "high_severity_by_type": dict(by_type),
        "embedding_matches": {k: len(v) for k, v in clusters.items() if k != "unknown"},
        "entry_points": [
            kg.functions[ep].name if ep in kg.functions else ep
            for ep in kg.entry_points[:20]
        ],
        "llm_analysis": llm_analysis
    }
    
    # Save report
    report_path = Path("CratD2C-Audit/full_scan_report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str))
    
    print(f"\n{'='*60}")
    print(f"Success Analysis complete in {total_time:.1f}s")
    print(f"Document Report: {report_path}")
    print(f"{'='*60}")
    
    return report

if __name__ == "__main__":
    main()
