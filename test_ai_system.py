#!/usr/bin/env python3
"""
HyperionAI System Test Script
Tests each component individually before full integration
"""

import json
import sys
import subprocess
import time
from pathlib import Path

def test_component(name: str, test_func):
    """Test a single component with error handling"""
    print(f"\nTest Testing {name}...")
    try:
        result = test_func()
        if result:
            print(f"Success {name}: PASSED")
            return True
        else:
            print(f"Failure {name}: FAILED")
            return False
    except Exception as e:
        print(f"Failure {name}: ERROR - {e}")
        return False

def test_python_environment():
    """Test Python and required packages"""
    import requests
    
    # Test requests library
    response = requests.get("https://httpbin.org/get", timeout=5)
    return response.status_code == 200

def test_hunter_agent():
    """Test Hunter Agent independently"""
    from hunter_agent import HunterAgent
    
    hunter = HunterAgent()
    
    # Create a simple test file
    test_content = """
    contract VulnerableContract {
        function withdraw() public {
            msg.sender.call{value: 1 ether}("");
            balance[msg.sender] = 0;
        }
        
        mapping(address => uint) public balance;
    }
    """
    
    test_file = Path("test_contract.sol")
    test_file.write_text(test_content)
    
    try:
        regions = hunter.scan_file(test_file)
        
        # Should find suspicious regions
        success = len(regions) > 0 and any("call" in r.content for r in regions)
        
        # Test triage
        high_suspicion = hunter.triage_for_llm(regions)
        
        return success and len(high_suspicion) > 0
        
    finally:
        if test_file.exists():
            test_file.unlink()

def test_ollama_connection():
    """Test Ollama connection and model availability"""
    from ollama_client import OllamaClient
    
    client = OllamaClient()
    
    # Test connection
    if not client.check_connection():
        return False
    
    # Test model listing
    models = client.list_available_models()
    
    # Check if at least one model is available
    return len(models) > 0

def test_simple_llm_prompt():
    """Test simple LLM interaction"""
    from ollama_client import OllamaClient, LLMRequest, AgentType
    
    client = OllamaClient()
    
    request = LLMRequest(
        agent=AgentType.HUNTER,
        prompt="What is a smart contract vulnerability?",
        context={}
    )
    
    response = client.generate(request)
    
    return response.confidence > 0.0 and len(response.response) > 10

def test_foundry_availability():
    """Test if Foundry is available"""
    try:
        result = subprocess.run(["forge", "--version"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def test_exploit_generator():
    """Test exploit generation (without actually running)"""
    from exploit_generator import ExploitGenerator, ExploitType
    
    generator = ExploitGenerator()
    
    # Test vulnerability data
    vuln_data = {
        "file": "TestContract.sol",
        "line": 10,
        "type": "reentrancy",
        "description": "Test vulnerability",
        "function": "withdraw"
    }
    
    try:
        vulnerability = generator.generate_exploit(vuln_data)
        
        # Should generate exploit code
        success = (
            vulnerability.vulnerability_type == ExploitType.REENTRANCY and
            len(vulnerability.exploit_code) > 100 and
            "contract" in vulnerability.exploit_code
        )
        
        return success
        
    except Exception as e:
        print(f"Exploit generation error: {e}")
        return False

def test_ai_orchestrator():
    """Test the AI orchestrator with minimal input"""
    from hyperion_ai import HyperionAI, AIAnalysisConfig
    
    config = AIAnalysisConfig(
        enable_llm_agents=False,  # Disable for basic test
        enable_exploit_validation=False,
        suspicion_threshold=0.5
    )
    
    ai = HyperionAI(config)
    
    # Test with a simple directory
    test_dir = Path(".")
    
    try:
        results = ai.analyze_directory(test_dir)
        
        # Should return results structure
        return (
            "stages" in results and
            "hunter" in results["stages"] and
            "final" in results
        )
        
    except Exception as e:
        print(f"AI orchestrator error: {e}")
        return False

def main():
    """Run all component tests"""
    print("AI HyperionAI Component Test Suite")
    print("=" * 50)
    
    tests = [
        ("Python Environment", test_python_environment),
        ("Hunter Agent", test_hunter_agent),
        ("Ollama Connection", test_ollama_connection),
        ("Simple LLM Prompt", test_simple_llm_prompt),
        ("Foundry Availability", test_foundry_availability),
        ("Exploit Generator", test_exploit_generator),
        ("AI Orchestrator", test_ai_orchestrator),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        success = test_component(test_name, test_func)
        results.append((test_name, success))
        time.sleep(1)  # Brief pause between tests
    
    # Summary
    print(f"\nChart Test Results Summary")
    print("=" * 50)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "Success PASS" if success else "Failure FAIL"
        print(f"{status:<8} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("Complete All components working! Ready for full integration test.")
        return 0
    elif passed >= total // 2:
        print("Warning  Some components missing. System will work with reduced functionality.")
        return 0
    else:
        print("Critical Critical components missing. Please run setup script.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
