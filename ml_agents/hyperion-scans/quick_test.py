#!/usr/bin/env python3
"""Quick test of local analysis components"""
import sys
from pathlib import Path

target = Path("../test-contracts/src")

print("="*50)
print("Testing Knowledge Graph...")
print("="*50)
from knowledge_graph import KnowledgeGraph
kg = KnowledgeGraph()
kg.build_from_directory(target)
attack = kg.get_attack_surface()
print(f"  Nodes: {len(kg.nodes)}")
print(f"  Edges: {len(kg.edges)}")
print(f"  Entry points: {len(attack['entry_points'])}")
print(f"  Attack paths: {len(attack['attack_paths'])}")
for f in attack['high_risk_functions'][:3]:
    print(f"  HIGH RISK: {f['name']} (risk: {f['risk_score']:.2f})")

print("\n" + "="*50)
print("Testing Embeddings...")
print("="*50)
from embedding_model import EmbeddingModel
em = EmbeddingModel()
embs = em.embed_directory(target, use_llm=False)
clusters = em.cluster_by_vulnerability(embs)
print(f"  Embeddings: {len(embs)}")
for vtype, emb_list in clusters.items():
    if vtype != "unknown" and len(emb_list) > 0:
        print(f"  {vtype}: {len(emb_list)} matches")

print("\n" + "="*50)
print("Testing Symbolic Execution...")
print("="*50)
from symbolic_execution import SymbolicExecutionEngine
se = SymbolicExecutionEngine()
results = se.analyze_directory(target)
print(f"  Violations: {results['total_violations']}")
print(f"  Critical: {results['by_severity'].get('critical', 0)}")
print(f"  High: {results['by_severity'].get('high', 0)}")

print("\n" + "="*50)
print("ALL LOCAL COMPONENTS WORKING!")
print("="*50)
