#!/usr/bin/env python3
"""
HyperionScan Full System Test

Tests the complete AI analysis pipeline:
1. Ollama connection with Mistral 7B
2. Knowledge Graph building
3. Embedding generation
4. Symbolic execution
5. LLM agents (if Ollama available)
"""

import sys
import json
from pathlib import Path

def test_ollama():
    """Test Ollama connection"""
    print("\n" + "="*60)
    print("Inspect Testing Ollama Connection")
    print("="*60)
    
    from ollama_client import OllamaClient
    
    client = OllamaClient()
    
    if client.check_connection():
        print("Success Ollama is running")
        models = client.list_available_models()
        print(f"Package Available models: {models}")
        
        if client.default_model:
            print(f"Target Auto-detected model: {client.default_model}")
            
            # Test a simple prompt
            from ollama_client import LLMRequest, AgentType
            request = LLMRequest(
                agent=AgentType.HUNTER,
                prompt="What is a reentrancy vulnerability in Solidity?",
                context={}
            )
            
            print("\nNote Testing LLM response...")
            response = client.generate(request)
            print(f"Model used: {response.model_used}")
            print(f"Response length: {len(response.response)} chars")
            print(f"Confidence: {response.confidence}")
            print(f"Time: {response.processing_time:.2f}s")
            print(f"\nResponse preview: {response.response[:200]}...")
            return True
        else:
            print("Warning  No models available")
            return False
    else:
        print("Failure Ollama not running")
        print("   Start with: ollama serve")
        return False

def test_knowledge_graph(directory: Path):
    """Test knowledge graph building"""
    print("\n" + "="*60)
    print("Chart Testing Knowledge Graph")
    print("="*60)
    
    from knowledge_graph import KnowledgeGraph
    
    graph = KnowledgeGraph()
    graph.build_from_directory(directory)
    
    attack_surface = graph.get_attack_surface()
    
    print(f"\nTrend Attack Surface Summary:")
    print(f"   Entry points: {len(attack_surface['entry_points'])}")
    print(f"   Sensitive operations: {len(attack_surface['sensitive_operations'])}")
    print(f"   Attack paths: {len(attack_surface['attack_paths'])}")
    
    if attack_surface['high_risk_functions']:
        print(f"\nCritical Top High-Risk Functions:")
        for func in attack_surface['high_risk_functions'][:3]:
            print(f"   {func['name']} (risk: {func['risk_score']:.2f})")
            print(f"      Risks: {', '.join(func['risks'])}")
    
    return True

def test_embeddings(directory: Path):
    """Test embedding generation"""
    print("\n" + "="*60)
    print("Step Testing Embedding Model")
    print("="*60)
    
    from embedding_model import EmbeddingModel
    
    model = EmbeddingModel()
    embeddings = model.embed_directory(directory, use_llm=False)
    
    clusters = model.cluster_by_vulnerability(embeddings)
    
    print(f"\nChart Vulnerability Distribution:")
    for vuln_type, embs in clusters.items():
        if vuln_type != "unknown" and len(embs) > 0:
            print(f"   {vuln_type}: {len(embs)} matches")
    
    return True

def test_symbolic_execution(directory: Path):
    """Test symbolic execution"""
    print("\n" + "="*60)
    print("Fast Testing Symbolic Execution")
    print("="*60)
    
    from symbolic_execution import SymbolicExecutionEngine
    
    engine = SymbolicExecutionEngine()
    results = engine.analyze_directory(directory)
    
    print(f"\nInspect Symbolic Execution Results:")
    print(f"   Total violations: {results['total_violations']}")
    print(f"   By severity: {results['by_severity']}")
    print(f"   By type: {results['by_type']}")
    
    if results['violations']:
        print(f"\nAlert Top Violations:")
        for v in results['violations'][:3]:
            print(f"   [{v['severity'].upper()}] {v['violation_type']}")
            print(f"      {v['description']}")
            print(f"      File: {v['file_path']}:{v['line_number']}")
    
    return True

def test_full_pipeline(directory: Path):
    """Test full AI pipeline"""
    print("\n" + "="*60)
    print("AI Testing Full AI Pipeline")
    print("="*60)
    
    from hyperion_ai import HyperionAI, AIAnalysisConfig
    
    config = AIAnalysisConfig(
        enable_llm_agents=True,  # Will auto-disable if Ollama not available
        enable_exploit_validation=False,  # Skip for quick test
        suspicion_threshold=0.5
    )
    
    ai = HyperionAI(config)
    results = ai.analyze_directory(directory)
    
    print(f"\nTarget FINAL RESULTS:")
    print(f"   Target: {results['target']}")
    print(f"   Total time: {results.get('total_processing_time', 0):.2f}s")
    print(f"   Stages completed: {list(results['stages'].keys())}")
    
    if 'final' in results:
        print(f"   Vulnerabilities: {results['final'].get('vulnerabilities_found', 0)}")
        print(f"   Recommendation: {results['final'].get('recommendation', 'N/A')}")
    
    # Save results
    output = Path("test_results.json")
    output.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nDocument Results saved to: {output}")
    
    return True

def main():
    """Run all tests"""
    print("AI HyperionScan Full System Test")
    print("================================")
    
    # Get test directory
    if len(sys.argv) > 1:
        test_dir = Path(sys.argv[1])
    else:
        # Try to find test-contracts
        possible_dirs = [
            Path("../test-contracts"),
            Path("./test-contracts"),
            Path("../examples"),
            Path("./examples"),
        ]
        test_dir = None
        for d in possible_dirs:
            if d.exists():
                test_dir = d
                break
        
        if not test_dir:
            print("Failure No test directory found")
            print("Usage: python test_full_system.py <directory>")
            sys.exit(1)
    
    print(f"\nFolder Test directory: {test_dir.absolute()}")
    
    # Run tests
    tests = [
        ("Ollama Connection", lambda: test_ollama()),
        ("Knowledge Graph", lambda: test_knowledge_graph(test_dir)),
        ("Embeddings", lambda: test_embeddings(test_dir)),
        ("Symbolic Execution", lambda: test_symbolic_execution(test_dir)),
        ("Full Pipeline", lambda: test_full_pipeline(test_dir)),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, "Success PASS" if success else "Failure FAIL"))
        except Exception as e:
            print(f"Failure Error in {test_name}: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, f"Failure ERROR: {str(e)[:50]}"))
    
    # Summary
    print("\n" + "="*60)
    print("Chart TEST SUMMARY")
    print("="*60)
    for test_name, result in results:
        print(f"   {result} - {test_name}")
    
    passed = sum(1 for _, r in results if "PASS" in r)
    print(f"\n   {passed}/{len(results)} tests passed")
    
    return 0 if passed == len(results) else 1

if __name__ == "__main__":
    sys.exit(main())
