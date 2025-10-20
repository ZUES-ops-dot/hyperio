#!/usr/bin/env python3
"""
Full HyperionAI Test - All 6 Stages
Runs complete analysis with Mistral LLM
"""
import sys
import json
import time
from pathlib import Path

# Test on a smaller subset for speed
TARGET_DIR = Path("../test-contracts/src")
# Use just the main contracts for LLM test (faster)
TEST_FILES = [
    "Controller.sol",
    "iToken.sol",
    "DefaultTimeLock.sol",
    "RewardDistributor.sol"
]

def main():
    print("=" * 60)
    print("AI HYPERION AI - FULL 6-STAGE ANALYSIS")
    print("=" * 60)
    
    start_time = time.time()
    
    # Stage 1: Hunter Agent
    print("\nLocation Stage 1: Hunter Agent - Pattern Triage")
    print("-" * 40)
    from hunter_agent import HunterAgent
    hunter = HunterAgent()
    all_regions = hunter.scan_directory(TARGET_DIR)
    high_suspicion = hunter.triage_for_llm(all_regions, threshold=0.5)
    print(f"   Total regions: {len(all_regions)}")
    print(f"   High suspicion: {len(high_suspicion)}")
    print(f"   Filtered: {len(all_regions) - len(high_suspicion)} ({100*(1-len(high_suspicion)/max(1,len(all_regions))):.0f}%)")
    
    # Stage 2: Knowledge Graph
    print("\nChart Stage 2: Knowledge Graph - Semantic Relationships")
    print("-" * 40)
    from knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    kg.build_from_directory(TARGET_DIR)
    attack_surface = kg.get_attack_surface()
    print(f"   Nodes: {len(kg.nodes)}")
    print(f"   Edges: {len(kg.edges)}")
    print(f"   Entry points: {len(attack_surface['entry_points'])}")
    print(f"   Attack paths: {len(attack_surface['attack_paths'])}")
    if attack_surface['high_risk_functions']:
        print(f"   Top risk: {attack_surface['high_risk_functions'][0]['name']} "
              f"(risk: {attack_surface['high_risk_functions'][0]['risk_score']:.2f})")
    
    # Stage 3: Embeddings
    print("\nStep Stage 3: Embedding Model - Code Fingerprinting")
    print("-" * 40)
    from embedding_model import EmbeddingModel
    em = EmbeddingModel()
    embeddings = em.embed_directory(TARGET_DIR, use_llm=False)
    clusters = em.cluster_by_vulnerability(embeddings)
    print(f"   Embeddings: {len(embeddings)}")
    for vtype, embs in clusters.items():
        if vtype != "unknown" and len(embs) > 0:
            print(f"   {vtype}: {len(embs)} matches")
    
    # Stage 4: Symbolic Execution
    print("\nFast Stage 4: Symbolic Execution - Path Analysis")
    print("-" * 40)
    from symbolic_execution import SymbolicExecutionEngine
    se = SymbolicExecutionEngine()
    sym_results = se.analyze_directory(TARGET_DIR)
    # Filter mocks
    critical_vulns = [v for v in sym_results['violations'] 
                      if v['severity'] == 'critical' and 'mock' not in v['file_path'].lower()]
    high_vulns = [v for v in sym_results['violations'] 
                  if v['severity'] == 'high' and 'mock' not in v['file_path'].lower()]
    print(f"   Critical: {len(critical_vulns)}")
    print(f"   High: {len(high_vulns)}")
    for v in critical_vulns[:3]:
        print(f"   Critical {v['violation_type']}: {Path(v['file_path']).name}:{v['line_number']}")
    
    # Stage 5: LLM Analysis (Mistral)
    print("\nAI Stage 5: LLM Agents - Mistral 7B Analysis")
    print("-" * 40)
    from ollama_client import OllamaClient, LLMRequest, AgentType
    
    client = OllamaClient()
    if not client.check_connection():
        print("   Failure Ollama not running - skipping LLM stage")
        print("   Start with: ollama serve")
        llm_results = None
    else:
        print(f"   Success Connected to Ollama")
        print(f"   Model: {client.default_model}")
        
        # Analyze top suspicious regions with LLM
        if high_suspicion:
            top_region = high_suspicion[0]
            print(f"   Analyzing: {top_region.file_path}")
            
            request = LLMRequest(
                agent=AgentType.HUNTER,
                prompt=f"Analyze this code for critical vulnerabilities:\n{top_region.content[:1500]}",
                context={"file": top_region.file_path, "suspicion": top_region.suspicion_score}
            )
            
            response = client.generate(request)
            print(f"   Response time: {response.processing_time:.1f}s")
            print(f"   Confidence: {response.confidence}")
            print(f"   Preview: {response.response[:200]}...")
            llm_results = {"response": response.response, "confidence": response.confidence}
        else:
            llm_results = None
    
    # Stage 6: Summary
    print("\n" + "=" * 60)
    print("Target FINAL ANALYSIS SUMMARY")
    print("=" * 60)
    
    total_time = time.time() - start_time
    
    print(f"""
   Target: {TARGET_DIR}
   Analysis Time: {total_time:.1f}s
   
   Chart METRICS:
   ├─ Code regions scanned: {len(all_regions)}
   ├─ Knowledge graph nodes: {len(kg.nodes)}
   ├─ Embeddings generated: {len(embeddings)}
   └─ Symbolic paths analyzed: {sym_results['total_violations']}
   
   Critical CRITICAL FINDINGS: {len(critical_vulns)}
   High HIGH FINDINGS: {len(high_vulns)}
   
   AI LLM: {'Connected (Mistral)' if llm_results else 'Not available'}
""")
    
    if critical_vulns:
        print("   Alert CRITICAL VULNERABILITIES:")
        for v in critical_vulns:
            print(f"      • {v['violation_type']} - {Path(v['file_path']).name}:{v['line_number']}")
            print(f"        {v['description'][:60]}...")
    
    # Save full report
    report = {
        "target": str(TARGET_DIR),
        "analysis_time_seconds": total_time,
        "stages": {
            "hunter": {"regions": len(all_regions), "suspicious": len(high_suspicion)},
            "knowledge_graph": {"nodes": len(kg.nodes), "edges": len(kg.edges)},
            "embeddings": {"total": len(embeddings)},
            "symbolic": {"critical": len(critical_vulns), "high": len(high_vulns)},
            "llm": {"available": llm_results is not None}
        },
        "critical_findings": critical_vulns,
        "high_findings": high_vulns[:10]  # Top 10
    }
    
    report_path = Path("hyperion_ai_report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n   Document Full report: {report_path}")
    
    print("\n" + "=" * 60)
    print("Success HYPERION AI ANALYSIS COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
