#!/usr/bin/env python3
"""
HyperionScan Knowledge Graph Engine

Builds a semantic knowledge graph of the codebase for:
- Contract relationships and inheritance
- Function call graphs
- State variable dependencies
- Cross-contract interactions
- Attack surface mapping
"""

import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

class NodeType(Enum):
    CONTRACT = "contract"
    FUNCTION = "function"
    VARIABLE = "variable"
    EVENT = "event"
    MODIFIER = "modifier"
    EXTERNAL_CALL = "external_call"
    STORAGE_SLOT = "storage_slot"

class EdgeType(Enum):
    INHERITS = "inherits"
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    EMITS = "emits"
    USES_MODIFIER = "uses_modifier"
    EXTERNAL_CALL = "external_call"
    DELEGATES_TO = "delegates_to"
    IMPORTS = "imports"

@dataclass
class Node:
    """Graph node representing a code entity"""
    id: str
    node_type: NodeType
    name: str
    file_path: str
    line_start: int
    line_end: int
    visibility: str = "internal"
    is_payable: bool = False
    is_view: bool = False
    modifiers: List[str] = field(default_factory=list)
    parameters: List[Dict] = field(default_factory=list)
    returns: List[Dict] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Edge:
    """Graph edge representing a relationship"""
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)

class KnowledgeGraph:
    """
    Semantic knowledge graph for smart contract analysis.
    
    Tracks:
    - Contract inheritance hierarchies
    - Function call graphs (internal + external)
    - State variable read/write patterns
    - Cross-contract interactions
    - Attack surface mapping
    """
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[str]] = defaultdict(list)
        
        # Indexes for fast lookups
        self.contracts: Dict[str, Node] = {}
        self.functions: Dict[str, Node] = {}
        self.variables: Dict[str, Node] = {}
        self.external_calls: List[Node] = []
        
        # Attack surface tracking
        self.entry_points: List[str] = []  # Public/external functions
        self.sensitive_operations: List[str] = []  # State changes, transfers, etc.
        self.attack_paths: List[List[str]] = []
    
    def add_node(self, node: Node) -> str:
        """Add a node to the graph"""
        self.nodes[node.id] = node
        
        # Update indexes
        if node.node_type == NodeType.CONTRACT:
            self.contracts[node.name] = node
        elif node.node_type == NodeType.FUNCTION:
            self.functions[node.id] = node
            if node.visibility in ["public", "external"]:
                self.entry_points.append(node.id)
        elif node.node_type == NodeType.VARIABLE:
            self.variables[node.id] = node
        elif node.node_type == NodeType.EXTERNAL_CALL:
            self.external_calls.append(node)
        
        return node.id
    
    def add_edge(self, edge: Edge):
        """Add an edge to the graph"""
        self.edges.append(edge)
        self.adjacency[edge.source_id].append(edge.target_id)
        self.reverse_adjacency[edge.target_id].append(edge.source_id)
    
    def parse_solidity_file(self, file_path: Path) -> List[Node]:
        """Parse a Solidity file and extract nodes/edges"""
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []
        
        nodes = []
        lines = content.split('\n')
        
        # Parse contracts
        contract_pattern = r'(contract|interface|library|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?'
        for match in re.finditer(contract_pattern, content):
            contract_type, name, inheritance = match.groups()
            line_num = content[:match.start()].count('\n') + 1
            
            node = Node(
                id=f"{file_path.stem}:{name}",
                node_type=NodeType.CONTRACT,
                name=name,
                file_path=str(file_path),
                line_start=line_num,
                line_end=line_num,
                attributes={"contract_type": contract_type, "inheritance": inheritance}
            )
            self.add_node(node)
            nodes.append(node)
            
            # Add inheritance edges
            if inheritance:
                for parent in re.findall(r'\w+', inheritance):
                    edge = Edge(
                        source_id=node.id,
                        target_id=f"*:{parent}",  # Wildcard for cross-file
                        edge_type=EdgeType.INHERITS
                    )
                    self.add_edge(edge)
        
        # Parse functions
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|private|internal|external|view|pure|payable|\s)*)'
        for match in re.finditer(func_pattern, content):
            name, params, modifiers = match.groups()
            line_num = content[:match.start()].count('\n') + 1
            
            visibility = "internal"
            for v in ["public", "external", "private", "internal"]:
                if v in modifiers:
                    visibility = v
                    break
            
            node = Node(
                id=f"{file_path.stem}:{name}",
                node_type=NodeType.FUNCTION,
                name=name,
                file_path=str(file_path),
                line_start=line_num,
                line_end=line_num,
                visibility=visibility,
                is_payable="payable" in modifiers,
                is_view="view" in modifiers or "pure" in modifiers
            )
            self.add_node(node)
            nodes.append(node)
        
        # Parse state variables
        var_pattern = r'(mapping\s*\([^)]+\)|address|uint\d*|int\d*|bool|bytes\d*|string)\s+(public|private|internal)?\s*(\w+)\s*[;=]'
        for match in re.finditer(var_pattern, content):
            var_type, visibility, name = match.groups()
            line_num = content[:match.start()].count('\n') + 1
            
            node = Node(
                id=f"{file_path.stem}:{name}",
                node_type=NodeType.VARIABLE,
                name=name,
                file_path=str(file_path),
                line_start=line_num,
                line_end=line_num,
                visibility=visibility or "internal",
                attributes={"var_type": var_type}
            )
            self.add_node(node)
            nodes.append(node)
        
        # Parse external calls
        call_patterns = [
            r'(\w+)\.call\{[^}]*\}\s*\([^)]*\)',  # .call{value:}()
            r'(\w+)\.transfer\s*\([^)]*\)',        # .transfer()
            r'(\w+)\.send\s*\([^)]*\)',            # .send()
            r'(\w+)\.delegatecall\s*\([^)]*\)',    # .delegatecall()
        ]
        
        for pattern in call_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                call_type = "call" if ".call" in match.group() else (
                    "transfer" if ".transfer" in match.group() else (
                    "send" if ".send" in match.group() else "delegatecall"
                ))
                
                node = Node(
                    id=f"{file_path.stem}:call:{line_num}",
                    node_type=NodeType.EXTERNAL_CALL,
                    name=f"external_{call_type}",
                    file_path=str(file_path),
                    line_start=line_num,
                    line_end=line_num,
                    attributes={"call_type": call_type, "target": match.group(1)}
                )
                self.add_node(node)
                nodes.append(node)
                
                # Mark as sensitive operation
                self.sensitive_operations.append(node.id)
        
        return nodes
    
    def build_from_directory(self, directory: Path, verbose: bool = True) -> int:
        """Build knowledge graph from all Solidity files in directory"""
        sol_files = list(directory.rglob("*.sol"))
        total_nodes = 0
        total_files = len(sol_files)
        
        print(f"Chart Building knowledge graph from {total_files} files...")
        
        # Stage 1: Parse all files
        if verbose:
            print(f"   Folder Stage 1/4: Parsing Solidity files...")
        
        contracts_found = 0
        functions_found = 0
        variables_found = 0
        
        for idx, sol_file in enumerate(sol_files):
            nodes = self.parse_solidity_file(sol_file)
            total_nodes += len(nodes)
            
            # Count by type
            file_contracts = sum(1 for n in nodes if n.node_type == NodeType.CONTRACT)
            file_functions = sum(1 for n in nodes if n.node_type == NodeType.FUNCTION)
            file_variables = sum(1 for n in nodes if n.node_type == NodeType.VARIABLE)
            
            contracts_found += file_contracts
            functions_found += file_functions
            variables_found += file_variables
            
            # Progress logging every 10 files or for files with significant content
            if verbose and (idx % 10 == 0 or file_contracts > 0):
                progress = (idx + 1) / total_files * 100
                print(f"   [{idx+1}/{total_files}] {progress:5.1f}% | {sol_file.name:<35} | "
                      f"C:{file_contracts} F:{file_functions} V:{file_variables}")
        
        if verbose:
            print(f"   Success Parsed: {contracts_found} contracts, {functions_found} functions, {variables_found} variables")
        
        # Stage 2: Resolve references
        if verbose:
            print(f"   Link Stage 2/4: Resolving cross-contract references...")
        self._resolve_references()
        if verbose:
            print(f"   Success Resolved {len(self.edges)} initial edges")
        
        # Stage 3: Build call graph
        if verbose:
            print(f"   Trend Stage 3/4: Building function call graph...")
        edges_before = len(self.edges)
        self._build_call_graph(directory, verbose=verbose)
        if verbose:
            print(f"   Success Added {len(self.edges) - edges_before} call edges")
        
        # Stage 4: Find attack paths
        if verbose:
            print(f"   Target Stage 4/4: Identifying attack paths...")
            print(f"      Entry points: {len(self.entry_points)}")
            print(f"      Sensitive ops: {len(self.sensitive_operations)}")
        self._find_attack_paths()
        
        print(f"Success Knowledge graph complete:")
        print(f"   Nodes: {len(self.nodes)}")
        print(f"   Edges: {len(self.edges)}")
        print(f"   Entry points: {len(self.entry_points)}")
        print(f"   Sensitive operations: {len(self.sensitive_operations)}")
        print(f"   Attack paths: {len(self.attack_paths)}")
        
        return total_nodes
    
    def _resolve_references(self):
        """Resolve wildcard references to actual nodes"""
        for edge in self.edges:
            if edge.target_id.startswith("*:"):
                target_name = edge.target_id[2:]
                # Find actual target
                for node_id, node in self.nodes.items():
                    if node.name == target_name:
                        edge.target_id = node_id
                        break
    
    def _build_call_graph(self, directory: Path, verbose: bool = False):
        """Build function call graph from code analysis (optimized)"""
        sol_files = list(directory.rglob("*.sol"))
        total_files = len(sol_files)
        edges_added = 0
        
        # Pre-build function name lookup for O(1) access
        func_names = {node.name: node_id for node_id, node in self.functions.items()}
        
        # Pre-compile single regex to find all function calls at once
        if func_names:
            all_func_pattern = re.compile(r'\b(' + '|'.join(re.escape(name) for name in func_names.keys()) + r')\s*\(')
        else:
            all_func_pattern = None
        
        for idx, sol_file in enumerate(sol_files):
            try:
                content = sol_file.read_text(encoding='utf-8')
            except:
                continue
            
            file_edges = 0
            
            # Get functions defined in this file
            file_funcs = [(fid, fn) for fid, fn in self.functions.items() if str(sol_file) == fn.file_path]
            
            if all_func_pattern and file_funcs:
                # Find all function calls in file at once
                called_funcs = set(all_func_pattern.findall(content))
                
                # Create edges from file's functions to called functions
                for func_id, func_node in file_funcs:
                    for called_name in called_funcs:
                        if called_name != func_node.name and called_name in func_names:
                            edge = Edge(
                                source_id=func_id,
                                target_id=func_names[called_name],
                                edge_type=EdgeType.CALLS
                            )
                            self.add_edge(edge)
                            file_edges += 1
            
            edges_added += file_edges
            
            # Progress logging every 10 files
            if verbose and (idx % 10 == 0 or idx == total_files - 1):
                progress = (idx + 1) / total_files * 100
                print(f"      [{idx+1}/{total_files}] {progress:5.1f}% | {sol_file.name:<30} | +{file_edges} edges")
    
    def _find_attack_paths(self):
        """Find potential attack paths from entry points to sensitive operations"""
        for entry in self.entry_points:
            for sensitive in self.sensitive_operations:
                path = self._find_path(entry, sensitive)
                if path:
                    self.attack_paths.append(path)
    
    def _find_path(self, start: str, end: str, max_depth: int = 10) -> Optional[List[str]]:
        """BFS to find path between two nodes"""
        if start == end:
            return [start]
        
        visited = {start}
        queue = [(start, [start])]
        
        while queue and len(visited) < max_depth * 10:
            current, path = queue.pop(0)
            
            for neighbor in self.adjacency.get(current, []):
                if neighbor == end:
                    return path + [neighbor]
                
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def get_attack_surface(self) -> Dict[str, Any]:
        """Get complete attack surface analysis"""
        return {
            "entry_points": [
                {
                    "id": ep,
                    "node": self.nodes[ep].__dict__ if ep in self.nodes else None
                }
                for ep in self.entry_points
            ],
            "sensitive_operations": [
                {
                    "id": so,
                    "node": self.nodes[so].__dict__ if so in self.nodes else None
                }
                for so in self.sensitive_operations
            ],
            "attack_paths": [
                {
                    "path": path,
                    "length": len(path),
                    "risk": self._calculate_path_risk(path)
                }
                for path in self.attack_paths
            ],
            "high_risk_functions": self._get_high_risk_functions(),
            "inheritance_issues": self._check_inheritance_issues()
        }
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for an attack path"""
        risk = 0.5
        
        for node_id in path:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                
                # Higher risk for payable functions
                if node.is_payable:
                    risk += 0.2
                
                # Higher risk for external calls
                if node.node_type == NodeType.EXTERNAL_CALL:
                    risk += 0.3
                    if node.attributes.get("call_type") == "delegatecall":
                        risk += 0.3  # delegatecall is most dangerous
        
        return min(risk, 1.0)
    
    def _get_high_risk_functions(self) -> List[Dict]:
        """Identify high-risk functions"""
        high_risk = []
        
        for func_id, func_node in self.functions.items():
            risk_score = 0.0
            risks = []
            
            # Check visibility
            if func_node.visibility in ["public", "external"]:
                risk_score += 0.1
                risks.append("publicly_accessible")
            
            # Check if payable
            if func_node.is_payable:
                risk_score += 0.3
                risks.append("handles_eth")
            
            # Check if it has paths to sensitive operations
            for path in self.attack_paths:
                if func_id in path:
                    risk_score += 0.2
                    risks.append("attack_path_member")
                    break
            
            # Check outgoing edges
            for neighbor in self.adjacency.get(func_id, []):
                if neighbor in self.sensitive_operations:
                    risk_score += 0.3
                    risks.append("calls_sensitive_ops")
                    break
            
            if risk_score >= 0.5:
                high_risk.append({
                    "function": func_id,
                    "name": func_node.name,
                    "risk_score": risk_score,
                    "risks": risks,
                    "file": func_node.file_path,
                    "line": func_node.line_start
                })
        
        return sorted(high_risk, key=lambda x: x["risk_score"], reverse=True)
    
    def _check_inheritance_issues(self) -> List[Dict]:
        """Check for inheritance-related issues"""
        issues = []
        
        for edge in self.edges:
            if edge.edge_type == EdgeType.INHERITS:
                # Check for diamond inheritance
                parent_id = edge.target_id
                child_id = edge.source_id
                
                # Check if parent inherits from same contract
                for other_edge in self.edges:
                    if (other_edge.edge_type == EdgeType.INHERITS and
                        other_edge.source_id != child_id and
                        other_edge.target_id == parent_id):
                        issues.append({
                            "type": "potential_diamond",
                            "contracts": [child_id, other_edge.source_id],
                            "common_parent": parent_id
                        })
        
        return issues
    
    def to_json(self) -> str:
        """Export graph to JSON"""
        return json.dumps({
            "nodes": {k: v.__dict__ for k, v in self.nodes.items()},
            "edges": [e.__dict__ for e in self.edges],
            "entry_points": self.entry_points,
            "sensitive_operations": self.sensitive_operations,
            "attack_paths": self.attack_paths
        }, indent=2, default=str)
    
    def query_node(self, node_id: str) -> Optional[Dict]:
        """Query a specific node with its relationships"""
        if node_id not in self.nodes:
            return None
        
        node = self.nodes[node_id]
        
        return {
            "node": node.__dict__,
            "outgoing": [
                {
                    "target": target_id,
                    "node": self.nodes.get(target_id).__dict__ if target_id in self.nodes else None
                }
                for target_id in self.adjacency.get(node_id, [])
            ],
            "incoming": [
                {
                    "source": source_id,
                    "node": self.nodes.get(source_id).__dict__ if source_id in self.nodes else None
                }
                for source_id in self.reverse_adjacency.get(node_id, [])
            ]
        }

def main():
    """Test knowledge graph"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python knowledge_graph.py <directory>")
        sys.exit(1)
    
    directory = Path(sys.argv[1])
    graph = KnowledgeGraph()
    graph.build_from_directory(directory)
    
    # Print attack surface
    attack_surface = graph.get_attack_surface()
    print(f"\nTarget Attack Surface Analysis:")
    print(f"   Entry Points: {len(attack_surface['entry_points'])}")
    print(f"   Sensitive Ops: {len(attack_surface['sensitive_operations'])}")
    print(f"   Attack Paths: {len(attack_surface['attack_paths'])}")
    
    print(f"\nCritical High Risk Functions:")
    for func in attack_surface['high_risk_functions'][:5]:
        print(f"   {func['name']} (risk: {func['risk_score']:.2f}) - {func['risks']}")
    
    # Save to JSON
    output_path = Path("knowledge_graph.json")
    output_path.write_text(graph.to_json())
    print(f"\nDocument Graph saved to: {output_path}")

if __name__ == "__main__":
    main()
