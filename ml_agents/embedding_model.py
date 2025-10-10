#!/usr/bin/env python3
"""
HyperionScan Embedding Model

Generates semantic embeddings for code using:
1. Local Ollama embeddings (using Mistral)
2. AST-based structural embeddings
3. Pattern-based fingerprints

Used for:
- Finding similar vulnerable code patterns
- Clustering related vulnerabilities
- Detecting code clones with vulnerabilities
- Semantic search across codebase
"""

import json
import hashlib
import re
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import defaultdict
import requests

@dataclass
class CodeEmbedding:
    """Embedding representation of a code snippet"""
    code_hash: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    
    # Different embedding types
    text_embedding: Optional[List[float]] = None  # From LLM
    structural_embedding: Optional[List[float]] = None  # From AST
    pattern_fingerprint: Optional[List[float]] = None  # From patterns
    
    # Combined embedding
    combined_embedding: Optional[List[float]] = None
    
    # Metadata
    language: str = "solidity"
    vulnerability_type: Optional[str] = None
    confidence: float = 0.0

class EmbeddingModel:
    """
    Multi-modal embedding model for code analysis.
    
    Combines:
    1. LLM text embeddings (semantic meaning)
    2. AST structural embeddings (code structure)
    3. Pattern fingerprints (security patterns)
    """
    
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.embedding_dim = 384  # Default dimension
        
        # Pattern vocabulary for fingerprinting
        self.security_patterns = {
            # Reentrancy patterns
            "external_call": r'\.call\{|\.transfer\(|\.send\(',
            "state_after_call": r'(call|transfer|send)[^;]*;[^}]*=',
            "balance_check": r'balance\[|balances\[|balanceOf\(',
            
            # Access control
            "only_owner": r'onlyOwner|require\s*\(\s*msg\.sender\s*==',
            "role_check": r'hasRole|isAdmin|isMinter',
            "tx_origin": r'tx\.origin',
            
            # Integer issues
            "unchecked_math": r'\+\+|\-\-|\+=|\-=|\*=|\/=',
            "safe_math": r'SafeMath|using\s+.*Math',
            
            # External interactions
            "delegatecall": r'\.delegatecall\(',
            "staticcall": r'\.staticcall\(',
            "low_level_call": r'\.call\(',
            
            # State changes
            "storage_write": r'storage\.|=.*\[|=.*mapping',
            "event_emit": r'emit\s+\w+',
            
            # Value handling
            "payable_function": r'payable',
            "value_transfer": r'\.value\(|msg\.value|transfer\(',
            "ether_math": r'ether|wei|gwei',
            
            # Control flow
            "require_statement": r'require\s*\(',
            "assert_statement": r'assert\s*\(',
            "revert_statement": r'revert\s*\(',
            "modifier_use": r'modifier\s+\w+',
            
            # Dangerous patterns
            "selfdestruct": r'selfdestruct|suicide',
            "assembly_block": r'assembly\s*\{',
            "inline_assembly": r'assembly\s*\(',
        }
        
        # Known vulnerable patterns (for similarity matching)
        self.vulnerable_signatures = self._load_vulnerable_signatures()
        
        # Embedding cache
        self.cache: Dict[str, CodeEmbedding] = {}
    
    def _load_vulnerable_signatures(self) -> List[Dict]:
        """Load known vulnerable code signatures"""
        # These are simplified representations of known vulnerabilities
        return [
            {
                "name": "classic_reentrancy",
                "pattern": ["external_call", "state_after_call", "balance_check"],
                "severity": "critical",
                "description": "Classic reentrancy: state change after external call"
            },
            {
                "name": "unchecked_send",
                "pattern": ["low_level_call", "value_transfer"],
                "severity": "high",
                "description": "Unchecked return value of send/call"
            },
            {
                "name": "tx_origin_auth",
                "pattern": ["tx_origin", "only_owner"],
                "severity": "high",
                "description": "Using tx.origin for authentication"
            },
            {
                "name": "dangerous_delegatecall",
                "pattern": ["delegatecall", "storage_write"],
                "severity": "critical",
                "description": "Delegatecall with storage modification"
            },
            {
                "name": "unprotected_selfdestruct",
                "pattern": ["selfdestruct"],
                "severity": "critical",
                "description": "Potentially unprotected selfdestruct"
            },
            {
                "name": "missing_access_control",
                "pattern": ["value_transfer", "storage_write"],
                "severity": "high",
                "description": "Sensitive operation without access control"
            }
        ]
    
    def get_ollama_embedding(self, text: str, model: str = "mistral:7b") -> Optional[List[float]]:
        """Get embedding from Ollama"""
        try:
            # Ollama embeddings endpoint
            response = requests.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": model, "prompt": text},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("embedding", None)
            else:
                print(f"Ollama embedding error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Error getting Ollama embedding: {e}")
            return None
    
    def get_structural_embedding(self, code: str) -> List[float]:
        """Generate structural embedding from code patterns"""
        embedding = [0.0] * len(self.security_patterns)
        
        for i, (pattern_name, pattern_regex) in enumerate(self.security_patterns.items()):
            matches = len(re.findall(pattern_regex, code, re.IGNORECASE))
            # Normalize with log to handle varying counts
            embedding[i] = math.log1p(matches)
        
        # Normalize to unit vector
        magnitude = math.sqrt(sum(x*x for x in embedding))
        if magnitude > 0:
            embedding = [x / magnitude for x in embedding]
        
        return embedding
    
    def get_pattern_fingerprint(self, code: str) -> List[float]:
        """Generate pattern-based fingerprint"""
        fingerprint = []
        
        # Count different code elements
        patterns_to_count = [
            r'function\s+\w+',     # Functions
            r'modifier\s+\w+',      # Modifiers
            r'event\s+\w+',         # Events
            r'mapping\s*\(',        # Mappings
            r'require\s*\(',        # Requires
            r'if\s*\(',            # Conditions
            r'for\s*\(',           # Loops
            r'while\s*\(',         # While loops
            r'\.call',             # External calls
            r'emit\s+',            # Event emissions
        ]
        
        for pattern in patterns_to_count:
            count = len(re.findall(pattern, code))
            fingerprint.append(math.log1p(count))
        
        # Add code complexity metrics
        lines = len(code.split('\n'))
        chars = len(code)
        nesting_depth = code.count('{') - code.count('}')
        
        fingerprint.extend([
            math.log1p(lines),
            math.log1p(chars / 100),
            math.log1p(abs(nesting_depth))
        ])
        
        # Normalize
        magnitude = math.sqrt(sum(x*x for x in fingerprint))
        if magnitude > 0:
            fingerprint = [x / magnitude for x in fingerprint]
        
        return fingerprint
    
    def embed_code(self, code: str, file_path: str, line_start: int, line_end: int,
                   use_llm: bool = True) -> CodeEmbedding:
        """Generate complete embedding for a code snippet"""
        
        # Check cache
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        if code_hash in self.cache:
            return self.cache[code_hash]
        
        # Create embedding object
        embedding = CodeEmbedding(
            code_hash=code_hash,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code[:500]  # Truncate for storage
        )
        
        # Get structural embedding (always fast)
        embedding.structural_embedding = self.get_structural_embedding(code)
        
        # Get pattern fingerprint (always fast)
        embedding.pattern_fingerprint = self.get_pattern_fingerprint(code)
        
        # Get LLM embedding if enabled
        if use_llm:
            embedding.text_embedding = self.get_ollama_embedding(
                f"Analyze this Solidity code for security vulnerabilities:\n{code[:1000]}"
            )
        
        # Combine embeddings
        embedding.combined_embedding = self._combine_embeddings(embedding)
        
        # Match against known vulnerable patterns
        vuln_match = self._match_vulnerable_pattern(embedding)
        if vuln_match:
            embedding.vulnerability_type = vuln_match["name"]
            embedding.confidence = vuln_match["similarity"]
        
        # Cache result
        self.cache[code_hash] = embedding
        
        return embedding
    
    def _combine_embeddings(self, embedding: CodeEmbedding) -> List[float]:
        """Combine different embedding types into one"""
        combined = []
        
        # Add structural embedding (weighted higher for security analysis)
        if embedding.structural_embedding:
            combined.extend([x * 1.5 for x in embedding.structural_embedding])
        
        # Add pattern fingerprint
        if embedding.pattern_fingerprint:
            combined.extend(embedding.pattern_fingerprint)
        
        # Add text embedding if available
        if embedding.text_embedding:
            # Take first N dimensions to keep size manageable
            combined.extend(embedding.text_embedding[:128])
        
        # Pad or truncate to fixed size
        target_size = 256
        if len(combined) < target_size:
            combined.extend([0.0] * (target_size - len(combined)))
        else:
            combined = combined[:target_size]
        
        # Normalize
        magnitude = math.sqrt(sum(x*x for x in combined))
        if magnitude > 0:
            combined = [x / magnitude for x in combined]
        
        return combined
    
    def _match_vulnerable_pattern(self, embedding: CodeEmbedding) -> Optional[Dict]:
        """Match embedding against known vulnerable patterns"""
        if not embedding.structural_embedding:
            return None
        
        best_match = None
        best_similarity = 0.0
        
        for vuln_sig in self.vulnerable_signatures:
            # Check which patterns from the signature are present
            pattern_indices = [
                list(self.security_patterns.keys()).index(p)
                for p in vuln_sig["pattern"]
                if p in self.security_patterns
            ]
            
            if not pattern_indices:
                continue
            
            # Calculate similarity based on pattern presence
            pattern_sum = sum(embedding.structural_embedding[i] for i in pattern_indices)
            similarity = pattern_sum / len(pattern_indices)
            
            if similarity > best_similarity and similarity > 0.3:
                best_similarity = similarity
                best_match = {
                    **vuln_sig,
                    "similarity": similarity
                }
        
        return best_match
    
    def cosine_similarity(self, emb1: List[float], emb2: List[float]) -> float:
        """Calculate cosine similarity between two embeddings"""
        if not emb1 or not emb2:
            return 0.0
        
        # Ensure same length
        min_len = min(len(emb1), len(emb2))
        emb1 = emb1[:min_len]
        emb2 = emb2[:min_len]
        
        dot_product = sum(a * b for a, b in zip(emb1, emb2))
        mag1 = math.sqrt(sum(a * a for a in emb1))
        mag2 = math.sqrt(sum(b * b for b in emb2))
        
        if mag1 == 0 or mag2 == 0:
            return 0.0
        
        return dot_product / (mag1 * mag2)
    
    def find_similar_code(self, query_embedding: CodeEmbedding, 
                          embeddings: List[CodeEmbedding],
                          top_k: int = 5) -> List[Tuple[CodeEmbedding, float]]:
        """Find most similar code snippets"""
        similarities = []
        
        for emb in embeddings:
            if emb.code_hash == query_embedding.code_hash:
                continue
            
            sim = self.cosine_similarity(
                query_embedding.combined_embedding,
                emb.combined_embedding
            )
            similarities.append((emb, sim))
        
        # Sort by similarity (descending)
        similarities.sort(key=lambda x: x[1], reverse=True)
        
        return similarities[:top_k]
    
    def cluster_by_vulnerability(self, embeddings: List[CodeEmbedding]) -> Dict[str, List[CodeEmbedding]]:
        """Cluster embeddings by vulnerability type"""
        clusters = defaultdict(list)
        
        for emb in embeddings:
            if emb.vulnerability_type:
                clusters[emb.vulnerability_type].append(emb)
            else:
                clusters["unknown"].append(emb)
        
        return dict(clusters)
    
    def embed_directory(self, directory: Path, use_llm: bool = False) -> List[CodeEmbedding]:
        """Embed all code in a directory"""
        embeddings = []
        sol_files = list(directory.rglob("*.sol"))
        
        print(f"Step Generating embeddings for {len(sol_files)} files...")
        
        for sol_file in sol_files:
            try:
                content = sol_file.read_text(encoding='utf-8')
            except:
                continue
            
            # Split into functions for more granular embeddings
            func_pattern = r'function\s+\w+[^{]*\{[^}]*(?:\{[^}]*\}[^}]*)*\}'
            
            for match in re.finditer(func_pattern, content, re.DOTALL):
                func_code = match.group()
                line_start = content[:match.start()].count('\n') + 1
                line_end = content[:match.end()].count('\n') + 1
                
                emb = self.embed_code(
                    func_code,
                    str(sol_file),
                    line_start,
                    line_end,
                    use_llm=use_llm
                )
                embeddings.append(emb)
        
        print(f"Success Generated {len(embeddings)} embeddings")
        
        # Show vulnerability distribution
        clusters = self.cluster_by_vulnerability(embeddings)
        print(f"Chart Vulnerability distribution:")
        for vuln_type, embs in clusters.items():
            if vuln_type != "unknown":
                print(f"   {vuln_type}: {len(embs)} matches")
        
        return embeddings
    
    def to_json(self, embeddings: List[CodeEmbedding]) -> str:
        """Export embeddings to JSON"""
        return json.dumps([
            {
                "code_hash": e.code_hash,
                "file_path": e.file_path,
                "line_start": e.line_start,
                "line_end": e.line_end,
                "vulnerability_type": e.vulnerability_type,
                "confidence": e.confidence,
                "snippet": e.code_snippet[:200]
            }
            for e in embeddings
        ], indent=2)

def main():
    """Test embedding model"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python embedding_model.py <directory>")
        sys.exit(1)
    
    directory = Path(sys.argv[1])
    model = EmbeddingModel()
    
    # Generate embeddings (without LLM for speed)
    embeddings = model.embed_directory(directory, use_llm=False)
    
    # Find vulnerabilities
    print(f"\nInspect Potential Vulnerabilities Found:")
    for emb in embeddings:
        if emb.vulnerability_type and emb.confidence > 0.5:
            print(f"   {emb.vulnerability_type} (conf: {emb.confidence:.2f})")
            print(f"      File: {emb.file_path}:{emb.line_start}")
            print()
    
    # Save embeddings
    output_path = Path("embeddings.json")
    output_path.write_text(model.to_json(embeddings))
    print(f"Document Embeddings saved to: {output_path}")

if __name__ == "__main__":
    main()
