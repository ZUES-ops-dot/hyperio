#!/usr/bin/env python3
"""
HyperionScan Ollama Integration - LLM Agent Communication

Connects to local Ollama instance for intelligent vulnerability analysis.
Each agent uses specialized models and prompts for optimal performance.
"""

import json
import time
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

class AgentType(Enum):
    HUNTER = "hunter"
    TAINT = "taint"
    CROSS = "cross"
    EXPLOIT = "exploit"
    SYNTH = "synth"

@dataclass
class LLMRequest:
    agent: AgentType
    prompt: str
    context: Dict[str, Any]
    model: Optional[str] = None

@dataclass
class LLMResponse:
    agent: AgentType
    response: str
    confidence: float
    processing_time: float
    model_used: str

class OllamaClient:
    """Client for communicating with local Ollama LLM instance"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.default_model = None  # Will be auto-detected
        
        # Preferred models in order of preference
        self.preferred_models = {
            AgentType.HUNTER: ["mistral:7b", "codellama:13b", "codellama:7b", "llama2:7b"],
            AgentType.TAINT: ["mistral:7b", "codellama:34b", "codellama:13b", "llama2:13b"],
            AgentType.CROSS: ["mistral:7b", "codellama:13b", "llama2:7b"],
            AgentType.EXPLOIT: ["mistral:7b", "codellama:34b", "codellama:13b"],
            AgentType.SYNTH: ["mistral:7b", "llama2:70b", "llama2:13b", "codellama:13b"],
        }
        
        # Auto-detect available model on init
        self._detect_available_model()
    
    def _detect_available_model(self):
        """Auto-detect the first available model from Ollama"""
        try:
            available = self.list_available_models()
            if available:
                # Prefer mistral if available
                for model in available:
                    if 'mistral' in model.lower():
                        self.default_model = model
                        print(f"Success Auto-detected Mistral model: {model}")
                        return
                # Otherwise use first available
                self.default_model = available[0]
                print(f"Success Auto-detected model: {self.default_model}")
        except Exception as e:
            print(f"Warning  Could not auto-detect model: {e}")
    
    def check_connection(self) -> bool:
        """Check if Ollama is running and accessible"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def list_available_models(self) -> List[str]:
        """Get list of available models from Ollama"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
        except Exception as e:
            print(f"Error getting models: {e}")
        return []
    
    def select_best_model(self, agent: AgentType) -> str:
        """Select the best available model for an agent"""
        available = self.list_available_models()
        
        # If we have a default model, use it
        if self.default_model and self.default_model in available:
            return self.default_model
        
        # Check preferred models in order
        preferences = self.preferred_models.get(agent, [])
        for model in preferences:
            # Check for exact match or partial match
            for avail in available:
                if model in avail or avail in model:
                    return avail
        
        # Last resort: use any available model
        if available:
            return available[0]
        
        raise ValueError("No models available in Ollama")
    
    def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate response from Ollama LLM"""
        start_time = time.time()
        
        # Select model - use request model, or auto-select best available
        if request.model:
            model = request.model
        else:
            model = self.select_best_model(request.agent)
        
        # Prepare prompt with context
        full_prompt = self._build_prompt(request.agent, request.prompt, request.context)
        
        # Call Ollama API
        payload = {
            "model": model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for security analysis
                "top_p": 0.9,
                "num_predict": 2048,
            }
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=120  # 2 minute timeout
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code}")
            
            data = response.json()
            processing_time = time.time() - start_time
            
            return LLMResponse(
                agent=request.agent,
                response=data.get("response", ""),
                confidence=self._extract_confidence(data),
                processing_time=processing_time,
                model_used=model
            )
            
        except Exception as e:
            processing_time = time.time() - start_time
            print(f"Error generating response: {e}")
            return LLMResponse(
                agent=request.agent,
                response=f"ERROR: {str(e)}",
                confidence=0.0,
                processing_time=processing_time,
                model_used=model
            )
    
    def _build_prompt(self, agent: AgentType, prompt: str, context: Dict[str, Any]) -> str:
        """Build specialized prompt for each agent type"""
        
        if agent == AgentType.HUNTER:
            return f"""You are a security code analyzer identifying suspicious code regions.

CONTEXT: {json.dumps(context, indent=2)}

TASK: {prompt}

Focus on:
- External calls with ETH/value
- Access control patterns
- State mutations after external calls
- User input handling

Respond with JSON format:
{{
    "suspicious_regions": [
        {{
            "file": "path",
            "lines": "start-end",
            "pattern": "type",
            "risk_score": 0.8,
            "reason": "why suspicious"
        }}
    ]
}}"""

        elif agent == AgentType.TAINT:
            return f"""You are a taint analysis expert tracking data flow in smart contracts.

CONTEXT: {json.dumps(context, indent=2)}

TASK: {prompt}

Focus on:
- User input sources (msg.sender, msg.value, parameters)
- Data flow to critical operations
- Sanitization and validation
- Indirect data flow through storage

Respond with JSON:
{{
    "taint_flows": [
        {{
            "source": "user_input_type",
            "sink": "critical_operation",
            "path": ["step1", "step2"],
            "vulnerability": "type",
            "exploitable": true
        }}
    ]
}}"""

        elif agent == AgentType.CROSS:
            return f"""You are a cross-contract interaction security expert.

CONTEXT: {json.dumps(context, indent=2)}

TASK: {prompt}

Focus on:
- Call graph analysis
- Multi-contract attack vectors
- Delegatecall risks
- Reentrancy across contracts

Respond with JSON:
{{
    "attack_vectors": [
        {{
            "vector": "type",
            "contracts": ["contract1", "contract2"],
            "entry_point": "function",
            "impact": "critical",
            "description": "attack scenario"
        }}
    ]
}}"""

        elif agent == AgentType.EXPLOIT:
            return f"""You are a smart contract exploit developer.

CONTEXT: {json.dumps(context, indent=2)}

TASK: {prompt}

Generate actual Foundry test code that exploits the vulnerability.

Requirements:
- Use Solidity ^0.8.0
- Include proper setup
- Demonstrate the exploit
- Include assertions

Respond with complete Foundry test code."""

        elif agent == AgentType.SYNTH:
            return f"""You are a security intelligence synthesizer.

CONTEXT: {json.dumps(context, indent=2)}

TASK: {prompt}

Synthesize all agent findings into final vulnerability report.

Include:
- Risk assessment
- Exploit scenarios
- Remediation steps
- Business impact

Respond with structured security report."""

        else:
            return f"Analyze this code: {prompt}\n\nContext: {json.dumps(context, indent=2)}"
    
    def _extract_confidence(self, response_data: Dict[str, Any]) -> float:
        """Extract confidence from Ollama response if available"""
        # Ollama doesn't provide confidence scores directly
        # We'll estimate based on response completeness
        response_text = response_data.get("response", "")
        
        if not response_text or response_text.startswith("ERROR"):
            return 0.0
        
        # Simple heuristic based on response length and structure
        if len(response_text) > 1000 and "{" in response_text:
            return 0.9
        elif len(response_text) > 500:
            return 0.7
        elif len(response_text) > 100:
            return 0.5
        else:
            return 0.3

class AgentOrchestrator:
    """Coordinates multiple LLM agents for comprehensive analysis"""
    
    def __init__(self, ollama_client: OllamaClient):
        self.client = ollama_client
        self.agents = list(AgentType)
    
    def analyze_with_all_agents(self, code_regions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run analysis through all specialized agents"""
        results = {
            "total_regions": len(code_regions),
            "agent_results": {},
            "processing_time": 0,
            "success": False
        }
        
        start_time = time.time()
        
        # Prepare context for agents
        context = {
            "code_regions": code_regions,
            "analysis_timestamp": time.time(),
            "total_files": len(set(r["file"] for r in code_regions))
        }
        
        # Run each agent
        for agent in self.agents:
            print(f"AI Running {agent.value} agent...")
            
            prompt = self._get_agent_prompt(agent, code_regions)
            request = LLMRequest(agent=agent, prompt=prompt, context=context)
            
            response = self.client.generate(request)
            results["agent_results"][agent.value] = {
                "response": response.response,
                "confidence": response.confidence,
                "processing_time": response.processing_time,
                "model": response.model_used
            }
            
            print(f"Success {agent.value} complete in {response.processing_time:.2f}s")
        
        results["processing_time"] = time.time() - start_time
        results["success"] = True
        
        return results
    
    def _get_agent_prompt(self, agent: AgentType, code_regions: List[Dict[str, Any]]) -> str:
        """Get specific prompt for each agent"""
        if agent == AgentType.HUNTER:
            return "Analyze these code regions and identify the most suspicious patterns that could indicate vulnerabilities."
        
        elif agent == AgentType.TAINT:
            return "Perform taint analysis on these code regions. Track how user input flows to critical operations."
        
        elif agent == AgentType.CROSS:
            return "Analyze cross-contract interactions. Identify attack vectors that span multiple contracts."
        
        elif agent == AgentType.EXPLOIT:
            return "Generate Foundry exploit code for the most critical vulnerabilities found in these regions."
        
        elif agent == AgentType.SYNTH:
            return "Synthesize all findings into a comprehensive security report with prioritized vulnerabilities."
        
        return "Analyze these code regions for security vulnerabilities."

def main():
    """Test Ollama integration"""
    client = OllamaClient()
    
    if not client.check_connection():
        print("Failure Ollama not running. Start with: ollama serve")
        return
    
    print("Success Ollama connected")
    models = client.list_available_models()
    print(f"Available models: {models}")
    
    # Test simple request
    request = LLMRequest(
        agent=AgentType.HUNTER,
        prompt="What are the most common Solidity vulnerabilities?",
        context={}
    )
    
    response = client.generate(request)
    print(f"\nResponse from {response.model_used}:")
    print(response.response[:500] + "..." if len(response.response) > 500 else response.response)
    print(f"\nConfidence: {response.confidence}, Time: {response.processing_time:.2f}s")

if __name__ == "__main__":
    main()
