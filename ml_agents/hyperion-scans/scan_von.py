#!/usr/bin/env python3
"""
Full HyperionScan analysis of von-smart-contract
"""
import sys
import json
import time
from pathlib import Path
from collections import defaultdict, Counter

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

TARGET_DIR = Path(__file__).parent / "von-smart-contract/contracts"
REPO_URL = "https://github.com/vameon/von-smart-contract"

def main():
    print("=" * 60)
    print("AI HYPERION AI - VON SMART CONTRACT AUDIT")
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
    if high_suspicion:
        print(f"   Top suspicious:")
        for r in high_suspicion[:3]:
            print(f"      • {Path(r.file_path).name}:{r.start_line} (score: {r.suspicion_score:.2f})")
    
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
    vuln_matches = {}
    for vtype, embs in clusters.items():
        if vtype != "unknown" and len(embs) > 0:
            print(f"   Warning {vtype}: {len(embs)} matches")
            vuln_matches[vtype] = len(embs)
    
    # =========================================================
    # Stage 4: Symbolic Execution
    # =========================================================
    print(f"\nFast Stage 4: Symbolic Execution - Critical Scan")
    print("-" * 40)
    from symbolic_execution import SymbolicExecutionEngine
    se = SymbolicExecutionEngine()
    sym_results = se.analyze_directory(TARGET_DIR)
    
    all_violations = sym_results['violations']
    critical = [v for v in all_violations if v['severity'] == 'critical']
    high = [v for v in all_violations if v['severity'] == 'high']
    
    print(f"\n   Critical Critical: {len(critical)}")
    print(f"   High High: {len(high)}")
    
    for v in critical:
        print(f"\n   [CRITICAL] {v['violation_type']}")
        print(f"      File: {Path(v['file_path']).name}:{v['line_number']}")
        print(f"      {v['description']}")
    
    # =========================================================
    # Stage 5: LLM Analysis
    # =========================================================
    print(f"\nAI Stage 5: LLM Analysis (Mistral)")
    print("-" * 40)
    from ollama_client import OllamaClient, LLMRequest, AgentType
    client = OllamaClient()
    
    llm_analysis = None
    if client.check_connection():
        print(f"   Success Connected: {client.default_model}")
        
        # Read main contract for LLM analysis
        main_contract = TARGET_DIR / "Vameon.sol"
        if main_contract.exists():
            code = main_contract.read_text()[:2000]
            req = LLMRequest(
                agent=AgentType.HUNTER,
                prompt=f"Analyze this Solidity contract for security vulnerabilities:\n\n{code}",
                context={"file": "Vameon.sol"}
            )
            print(f"   Analyzing Vameon.sol...")
            resp = client.generate(req)
            print(f"   Response time: {resp.processing_time:.1f}s")
            print(f"   Confidence: {resp.confidence}")
            llm_analysis = resp.response
            print(f"\n   LLM Findings:")
            print(f"   {resp.response[:500]}...")
    else:
        print("   Warning Ollama not available")
    
    # =========================================================
    # Stage 6: Generate Report
    # =========================================================
    total_time = time.time() - start_time
    
    print(f"\n{'='*60}")
    print("Checklist AUDIT SUMMARY")
    print(f"{'='*60}")
    print(f"""
   Repository: {REPO_URL}
   Files: {len(sol_files)}
   Functions: {len(kg.functions)}
   Variables: {len(kg.variables)}
   
   Critical Critical: {len(critical)}
   High High: {len(high)}
   
   Analysis Time: {total_time:.1f}s
""")
    
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
                "exploit_conditions": v.get('exploit_conditions', []),
                "taint_path": v.get('taint_path', [])
            }
            for v in critical
        ],
        "high_severity": [
            {
                "type": v['violation_type'],
                "file": Path(v['file_path']).name,
                "line": v['line_number'],
                "description": v['description']
            }
            for v in high
        ],
        "embedding_matches": vuln_matches,
        "entry_points": [
            kg.functions[ep].name if ep in kg.functions else ep
            for ep in kg.entry_points
        ],
        "llm_analysis": llm_analysis[:1000] if llm_analysis else None
    }
    
    # Save report
    report_path = Path(__file__).parent / "von-smart-contract-Audit/full_scan_report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"   Document Report saved: {report_path}")
    
    print(f"\n{'='*60}")
    print(f"Success AUDIT COMPLETE")
    print(f"{'='*60}")
    
    return report

if __name__ == "__main__":
    main()
