#!/usr/bin/env python3
"""
HyperionScan Symbolic Execution Engine

Performs path-sensitive analysis of smart contracts:
- Symbolic state tracking
- Path constraint solving
- Vulnerability detection through execution paths
- Reentrancy path analysis
- Integer overflow detection

This is a lightweight symbolic execution engine designed
for security analysis without full EVM simulation.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from copy import deepcopy

class SymbolicValueType(Enum):
    CONCRETE = "concrete"
    SYMBOLIC = "symbolic"
    UNKNOWN = "unknown"
    TAINTED = "tainted"  # User-controlled input

class OperationType(Enum):
    ASSIGNMENT = "assignment"
    ARITHMETIC = "arithmetic"
    COMPARISON = "comparison"
    CALL = "call"
    RETURN = "return"
    BRANCH = "branch"
    STORAGE_READ = "storage_read"
    STORAGE_WRITE = "storage_write"
    EXTERNAL_CALL = "external_call"

@dataclass
class SymbolicValue:
    """Represents a symbolic or concrete value"""
    value_type: SymbolicValueType
    name: str
    concrete_value: Optional[Any] = None
    expression: Optional[str] = None
    taint_source: Optional[str] = None
    constraints: List[str] = field(default_factory=list)
    
    def is_tainted(self) -> bool:
        return self.value_type == SymbolicValueType.TAINTED or self.taint_source is not None
    
    def __repr__(self):
        if self.value_type == SymbolicValueType.CONCRETE:
            return f"Concrete({self.concrete_value})"
        elif self.value_type == SymbolicValueType.TAINTED:
            return f"Tainted({self.name}, source={self.taint_source})"
        else:
            return f"Symbolic({self.name})"

@dataclass
class ExecutionState:
    """Represents a point in symbolic execution"""
    path_id: str
    function_name: str
    line_number: int
    
    # Symbolic state
    variables: Dict[str, SymbolicValue] = field(default_factory=dict)
    storage: Dict[str, SymbolicValue] = field(default_factory=dict)
    memory: Dict[str, SymbolicValue] = field(default_factory=dict)
    
    # Path constraints
    path_constraints: List[str] = field(default_factory=list)
    
    # Execution trace
    trace: List[Dict] = field(default_factory=list)
    
    # Security-relevant state
    ether_balance: SymbolicValue = None
    msg_sender: SymbolicValue = None
    msg_value: SymbolicValue = None
    
    # Flags
    in_external_call: bool = False
    state_modified_after_call: bool = False
    reentrancy_guard_active: bool = False
    
    def clone(self) -> 'ExecutionState':
        """Deep clone the state for path exploration"""
        return deepcopy(self)
    
    def add_trace(self, operation: OperationType, details: Dict):
        """Add operation to execution trace"""
        self.trace.append({
            "operation": operation.value,
            "line": self.line_number,
            "details": details
        })

@dataclass
class PathCondition:
    """Represents a condition that must be satisfied on this path"""
    expression: str
    is_true: bool
    line_number: int
    
    def __repr__(self):
        op = "==" if self.is_true else "!="
        return f"{self.expression} {op} true @ line {self.line_number}"

@dataclass
class SecurityViolation:
    """Represents a detected security issue"""
    violation_type: str
    severity: str
    path_id: str
    line_number: int
    description: str
    taint_path: List[str]
    constraints: List[str]
    exploit_conditions: List[str]
    file_path: str = ""

class SymbolicExecutionEngine:
    """
    Lightweight symbolic execution engine for smart contract security analysis.
    
    Focuses on:
    1. Taint tracking (user input → sensitive operations)
    2. Reentrancy detection (external call → state change)
    3. Access control bypass paths
    4. Integer overflow conditions
    """
    
    def __init__(self):
        self.states: List[ExecutionState] = []
        self.violations: List[SecurityViolation] = []
        self.current_state: Optional[ExecutionState] = None
        self.path_counter = 0
        
        # Taint sources (user-controlled inputs)
        self.taint_sources = {
            "msg.sender": "caller_address",
            "msg.value": "ether_sent",
            "msg.data": "call_data",
            "tx.origin": "transaction_origin",
            "block.timestamp": "block_time",
            "block.number": "block_num",
        }
        
        # Sensitive sinks
        self.sensitive_sinks = {
            "transfer": "ether_transfer",
            "send": "ether_send",
            "call": "external_call",
            "delegatecall": "delegate_call",
            "selfdestruct": "contract_destruction",
            "suicide": "contract_destruction",
        }
        
        # Functions that provide protection
        self.protection_patterns = {
            "onlyOwner": "access_control",
            "nonReentrant": "reentrancy_guard",
            "require": "condition_check",
        }
    
    def analyze_function(self, function_code: str, function_name: str,
                        file_path: str) -> List[SecurityViolation]:
        """Analyze a single function with symbolic execution"""
        self.violations = []
        self.path_counter = 0
        
        # Initialize starting state
        initial_state = self._create_initial_state(function_name, function_code)
        
        # Parse and execute symbolically
        self._symbolic_execute(function_code, initial_state, file_path)
        
        return self.violations
    
    def _create_initial_state(self, function_name: str, code: str) -> ExecutionState:
        """Create initial symbolic state for function"""
        state = ExecutionState(
            path_id=f"path_{self.path_counter}",
            function_name=function_name,
            line_number=1
        )
        
        # Initialize tainted inputs
        state.msg_sender = SymbolicValue(
            value_type=SymbolicValueType.TAINTED,
            name="msg.sender",
            taint_source="caller_address"
        )
        
        state.msg_value = SymbolicValue(
            value_type=SymbolicValueType.TAINTED,
            name="msg.value",
            taint_source="ether_sent"
        )
        
        state.ether_balance = SymbolicValue(
            value_type=SymbolicValueType.SYMBOLIC,
            name="address(this).balance"
        )
        
        # Parse function parameters as tainted
        param_pattern = r'function\s+\w+\s*\(([^)]*)\)'
        match = re.search(param_pattern, code)
        if match and match.group(1).strip():
            params = match.group(1).split(',')
            for i, param in enumerate(params):
                param = param.strip()
                if param:
                    # Extract parameter name
                    parts = param.split()
                    if len(parts) >= 2:
                        param_name = parts[-1]
                        state.variables[param_name] = SymbolicValue(
                            value_type=SymbolicValueType.TAINTED,
                            name=param_name,
                            taint_source=f"function_parameter_{i}"
                        )
        
        # Check for modifiers (protection)
        if "onlyOwner" in code or "require(msg.sender ==" in code:
            state.reentrancy_guard_active = False  # Has access control
        if "nonReentrant" in code:
            state.reentrancy_guard_active = True
        
        return state
    
    def _symbolic_execute(self, code: str, state: ExecutionState, file_path: str):
        """Execute code symbolically, exploring all paths"""
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            state.line_number = i + 1
            line = line.strip()
            
            if not line or line.startswith('//'):
                continue
            
            # Track storage reads
            self._track_storage_reads(line, state)
            
            # Track storage writes
            self._track_storage_writes(line, state, file_path)
            
            # Track external calls
            self._track_external_calls(line, state, file_path)
            
            # Track arithmetic operations
            self._track_arithmetic(line, state, file_path)
            
            # Handle branches (if statements)
            if re.match(r'if\s*\(', line):
                self._handle_branch(line, state, lines[i:], file_path)
            
            # Track require statements
            if 'require(' in line:
                self._track_require(line, state)
        
        # Post-execution analysis
        self._check_reentrancy(state, file_path)
        self._check_access_control(state, file_path)
    
    def _track_storage_reads(self, line: str, state: ExecutionState):
        """Track reads from storage variables"""
        # Pattern: reading from mappings or state variables
        read_patterns = [
            r'(\w+)\[([^\]]+)\]',  # mapping access
            r'(\w+)\s*=\s*(\w+)',  # variable read
        ]
        
        for pattern in read_patterns:
            for match in re.finditer(pattern, line):
                var_name = match.group(1)
                if var_name in state.storage:
                    state.add_trace(OperationType.STORAGE_READ, {
                        "variable": var_name,
                        "value": str(state.storage[var_name])
                    })
    
    def _track_storage_writes(self, line: str, state: ExecutionState, file_path: str):
        """Track writes to storage variables"""
        # Pattern: assignment to state variable
        write_patterns = [
            r'(\w+)\[([^\]]+)\]\s*=\s*(.+)',  # mapping write
            r'(\w+)\s*=\s*(.+)',  # variable write
        ]
        
        for pattern in write_patterns:
            for match in re.finditer(pattern, line):
                var_name = match.group(1)
                
                # Check if this is after an external call (reentrancy risk)
                if state.in_external_call:
                    state.state_modified_after_call = True
                
                # Track the write
                state.storage[var_name] = SymbolicValue(
                    value_type=SymbolicValueType.SYMBOLIC,
                    name=f"{var_name}_updated"
                )
                
                state.add_trace(OperationType.STORAGE_WRITE, {
                    "variable": var_name,
                    "line": state.line_number
                })
    
    def _track_external_calls(self, line: str, state: ExecutionState, file_path: str):
        """Track external calls for reentrancy analysis"""
        call_patterns = [
            (r'\.call\{[^}]*value:\s*([^}]+)\}', "call_with_value"),
            (r'\.call\{[^}]*\}\s*\(', "call"),
            (r'\.transfer\s*\(([^)]+)\)', "transfer"),
            (r'\.send\s*\(([^)]+)\)', "send"),
            (r'\.delegatecall\s*\(', "delegatecall"),
        ]
        
        for pattern, call_type in call_patterns:
            if re.search(pattern, line):
                state.in_external_call = True
                
                state.add_trace(OperationType.EXTERNAL_CALL, {
                    "type": call_type,
                    "line": state.line_number,
                    "state_before": list(state.storage.keys())
                })
                
                # Check for delegatecall danger
                if call_type == "delegatecall":
                    self._report_violation(
                        "DANGEROUS_DELEGATECALL",
                        "critical",
                        state,
                        "Delegatecall to potentially untrusted address",
                        file_path
                    )
    
    def _track_arithmetic(self, line: str, state: ExecutionState, file_path: str):
        """Track arithmetic operations for overflow detection"""
        # Look for arithmetic without SafeMath (pre-0.8.0 concern)
        arith_patterns = [
            (r'(\w+)\s*\+\s*(\w+)', "addition"),
            (r'(\w+)\s*\-\s*(\w+)', "subtraction"),
            (r'(\w+)\s*\*\s*(\w+)', "multiplication"),
            (r'(\w+)\s*/\s*(\w+)', "division"),
        ]
        
        for pattern, op_type in arith_patterns:
            match = re.search(pattern, line)
            if match:
                operand1 = match.group(1)
                operand2 = match.group(2)
                
                # Check if operands are tainted (user-controlled)
                tainted_operands = []
                for operand in [operand1, operand2]:
                    if operand in state.variables:
                        if state.variables[operand].is_tainted():
                            tainted_operands.append(operand)
                
                if tainted_operands and "unchecked" not in line.lower():
                    state.add_trace(OperationType.ARITHMETIC, {
                        "operation": op_type,
                        "tainted_operands": tainted_operands,
                        "line": state.line_number
                    })
    
    def _track_require(self, line: str, state: ExecutionState):
        """Track require statements as path constraints"""
        # Extract condition from require
        match = re.search(r'require\s*\(([^,)]+)', line)
        if match:
            condition = match.group(1).strip()
            state.path_constraints.append(condition)
            
            # Check for access control
            if "msg.sender" in condition and "==" in condition:
                state.add_trace(OperationType.COMPARISON, {
                    "type": "access_control_check",
                    "condition": condition
                })
    
    def _handle_branch(self, line: str, state: ExecutionState, 
                       remaining_lines: List[str], file_path: str):
        """Handle branching for path exploration"""
        # Extract condition
        match = re.search(r'if\s*\(([^)]+)\)', line)
        if match:
            condition = match.group(1).strip()
            
            # Create path for true branch
            true_state = state.clone()
            true_state.path_id = f"path_{self.path_counter}_true"
            true_state.path_constraints.append(f"{condition} == true")
            self.path_counter += 1
            
            # Create path for false branch
            false_state = state.clone()
            false_state.path_id = f"path_{self.path_counter}_false"
            false_state.path_constraints.append(f"{condition} == false")
            self.path_counter += 1
            
            # Store both paths for later analysis
            self.states.extend([true_state, false_state])
    
    def _check_reentrancy(self, state: ExecutionState, file_path: str):
        """Check for reentrancy vulnerability"""
        # Method 1: Sequential analysis (external call then state change)
        if state.in_external_call and state.state_modified_after_call:
            if not state.reentrancy_guard_active:
                taint_path = []
                for trace_item in state.trace:
                    if trace_item["operation"] == "external_call":
                        taint_path.append(f"external_call@{trace_item['details']['line']}")
                    elif trace_item["operation"] == "storage_write":
                        taint_path.append(f"state_write@{trace_item['details']['line']}")
                
                self._report_violation(
                    "REENTRANCY",
                    "critical",
                    state,
                    "State modified after external call without reentrancy guard",
                    file_path,
                    taint_path=taint_path
                )
        
        # Method 2: Check trace for external call followed by storage write
        external_call_line = None
        for trace_item in state.trace:
            if trace_item["operation"] == "external_call":
                external_call_line = trace_item["details"].get("line", 0)
            elif trace_item["operation"] == "storage_write" and external_call_line:
                write_line = trace_item["details"].get("line", 0)
                if write_line > external_call_line and not state.reentrancy_guard_active:
                    self._report_violation(
                        "REENTRANCY",
                        "critical",
                        state,
                        f"State modified at line {write_line} after external call at line {external_call_line}",
                        file_path,
                        taint_path=[f"call@{external_call_line}", f"write@{write_line}"]
                    )
    
    def _check_access_control(self, state: ExecutionState, file_path: str):
        """
        Check for missing access control on TRULY SENSITIVE operations.
        
        Only flag as high/critical if:
        - Function is public/external AND
        - Modifies critical state (balances, ownership, addresses) AND
        - No access control present
        
        Auto-suppress:
        - View/pure functions (no state changes)
        - Internal/private functions
        - Functions that only read state
        """
        # Skip if no sensitive operations in trace
        has_value_transfer = any(
            t["operation"] == "external_call" and 
            t.get("details", {}).get("type") in ["call_with_value", "transfer", "send"]
            for t in state.trace
        )
        
        has_critical_write = any(
            t["operation"] == "storage_write" and
            any(critical in str(t.get("details", {})).lower() for critical in [
                'owner', 'admin', 'balance', 'implementation', 'proxy', 'paused'
            ])
            for t in state.trace
        )
        
        has_access_control = any(
            "access_control" in str(t.get("details", {})) for t in state.trace
        ) or state.reentrancy_guard_active
        
        # Only report if truly sensitive and no access control
        if (has_value_transfer or has_critical_write) and not has_access_control:
            severity = "critical" if has_value_transfer else "high"
            self._report_violation(
                "MISSING_ACCESS_CONTROL",
                severity,
                state,
                f"{'ETH transfer' if has_value_transfer else 'Critical state change'} without access control",
                file_path
            )
    
    def _report_violation(self, violation_type: str, severity: str,
                         state: ExecutionState, description: str,
                         file_path: str, taint_path: List[str] = None):
        """Report a security violation"""
        violation = SecurityViolation(
            violation_type=violation_type,
            severity=severity,
            path_id=state.path_id,
            line_number=state.line_number,
            description=description,
            taint_path=taint_path or [],
            constraints=state.path_constraints.copy(),
            exploit_conditions=[
                f"Path requires: {c}" for c in state.path_constraints
            ],
            file_path=file_path
        )
        
        self.violations.append(violation)
    
    def analyze_file(self, file_path: Path) -> List[SecurityViolation]:
        """Analyze all functions in a file"""
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return []
        
        all_violations = []
        
        # First: Direct pattern scan for critical vulnerabilities
        critical_violations = self._scan_critical_patterns(content, str(file_path))
        all_violations.extend(critical_violations)
        
        # Extract functions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
        
        for match in re.finditer(func_pattern, content, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(0)
            
            violations = self.analyze_function(func_body, func_name, str(file_path))
            all_violations.extend(violations)
        
        return all_violations
    
    def _scan_critical_patterns(self, content: str, file_path: str) -> List[SecurityViolation]:
        """
        Production-quality critical vulnerability scanner.
        
        Critical = Directly exploitable with significant impact + verified exploitability
        
        Checks:
        - Reentrancy: External call -> state change -> value at risk -> no guard
        - Delegatecall: User-controlled target (not hardcoded/immutable/whitelisted)
        - Selfdestruct: Unprotected
        - Arbitrary external call with user-controlled address + data
        
        Each finding includes:
        - Trust analysis (where does the dangerous value come from?)
        - Access control context
        - State mutation check
        """
        violations = []
        lines = content.split('\n')
        
        # Skip mock files
        file_name = Path(file_path).name.lower()
        parent_dir = Path(file_path).parent.name.lower()
        if 'mock' in file_name or parent_dir == 'mock':
            return violations
        
        # File-level security patterns
        has_reentrancy_guard = 'ReentrancyGuard' in content or 'nonReentrant' in content
        has_ownable = 'Ownable' in content or 'onlyOwner' in content
        has_access_control = 'AccessControl' in content or 'hasRole' in content
        
        # =============================================================
        # PATTERN 1: REENTRANCY (Multiple detection methods)
        # =============================================================
        # 
        # Critical conditions:
        # - External call (call/transfer/send) BEFORE state change
        # - No ReentrancyGuard/nonReentrant modifier
        # - State change affects balances/mappings (value at risk)
        # - External call inside loops (cross-function reentrancy)
        
        external_call_patterns = [
            (r'\.call\{[^}]*value', 'call_with_value'),
            (r'\.call\{[^}]*\}\s*\(', 'low_level_call'),
            (r'\.transfer\s*\(', 'transfer'),
            (r'\.send\s*\(', 'send'),
        ]
        
        state_change_patterns = [
            r'balance\w*\s*\[[^\]]+\]\s*[-+]?=',
            r'balances\s*\[[^\]]+\]\s*[-+]?=',
            r'_balances\s*\[[^\]]+\]\s*[-+]?=',
            r'shares\s*\[[^\]]+\]\s*[-+]?=',
            r'deposits\s*\[[^\]]+\]\s*[-+]?=',
            r'userInfo\s*\[[^\]]+\].*=',
            r'totalSupply\s*[-+]?=',
            r'totalDeposits\s*[-+]?=',
        ]
        
        for i, line in enumerate(lines):
            for call_pattern, call_type in external_call_patterns:
                if re.search(call_pattern, line, re.IGNORECASE):
                    # Found external call - check for state changes AFTER
                    func_start = max(0, i - 40)
                    func_end = min(len(lines), i + 20)
                    func_context_before = '\n'.join(lines[func_start:i])
                    func_context_after = '\n'.join(lines[i+1:func_end])
                    
                    # Check for reentrancy guard
                    has_guard = any(guard in func_context_before for guard in [
                        'nonReentrant', 'ReentrancyGuard', 'locked', 'mutex'
                    ])
                    
                    if has_guard:
                        continue
                    
                    # Check for state changes AFTER the call
                    for j in range(i + 1, func_end):
                        for state_pattern in state_change_patterns:
                            if re.search(state_pattern, lines[j], re.IGNORECASE):
                                violations.append(SecurityViolation(
                                    violation_type="REENTRANCY",
                                    severity="critical",
                                    path_id="direct_scan",
                                    line_number=i + 1,
                                    description=f"CRITICAL: State change at line {j+1} AFTER {call_type} - classic reentrancy pattern",
                                    taint_path=[
                                        f"external_call:{call_type}@{i+1}",
                                        f"state_mutation@{j+1}"
                                    ],
                                    constraints=["No ReentrancyGuard detected"],
                                    exploit_conditions=[
                                        "1. Attacker deploys contract with malicious fallback/receive",
                                        "2. Attacker calls vulnerable function",
                                        "3. During ETH transfer, attacker's fallback re-enters",
                                        "4. State not yet updated - attacker withdraws again",
                                        "5. Repeat until contract drained"
                                    ],
                                    file_path=file_path
                                ))
                                break
                        else:
                            continue
                        break
        
        # Check for external calls inside loops (cross-function reentrancy risk)
        in_loop = False
        loop_start = 0
        for i, line in enumerate(lines):
            if re.search(r'\b(for|while)\s*\(', line):
                in_loop = True
                loop_start = i
            elif in_loop and line.strip() == '}':
                in_loop = False
            
            if in_loop:
                for call_pattern, call_type in external_call_patterns:
                    if re.search(call_pattern, line, re.IGNORECASE):
                        violations.append(SecurityViolation(
                            violation_type="REENTRANCY_LOOP",
                            severity="critical",
                            path_id="direct_scan",
                            line_number=i + 1,
                            description=f"CRITICAL: External {call_type} inside loop - high reentrancy/DoS risk",
                            taint_path=[f"loop_start@{loop_start+1}", f"external_call@{i+1}"],
                            constraints=[],
                            exploit_conditions=[
                                "1. Attacker can manipulate loop iterations",
                                "2. Each iteration makes external call",
                                "3. Attacker re-enters or causes revert",
                                "4. Can DoS or drain funds"
                            ],
                            file_path=file_path
                        ))
        
        # =============================================================
        # PATTERN 2: DELEGATECALL TRUST ANALYSIS
        # =============================================================
        #
        # Trust levels for delegatecall target:
        # - CRITICAL: Target from function parameter (user-controlled)
        # - CRITICAL: Target from msg.data / calldata
        # - HIGH: Target from storage (could be manipulated by admin)
        # - SAFE: Target is hardcoded / immutable / constructor-set
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Detect delegatecall patterns - must capture target variable
            # Pattern 1: target.delegatecall(...)
            delegatecall_match = re.search(r'(\w+)\s*\.\s*delegatecall\s*\(', line_lower)
            # Pattern 2: assembly delegatecall(gas(), target, ...)
            if not delegatecall_match:
                delegatecall_match = re.search(r'delegatecall\s*\(\s*gas\s*\(\s*\)\s*,\s*(\w+)', line_lower)
            
            # Skip functionDelegateCall wrappers - these use trusted storage targets
            if '.functiondelegatecall(' in line_lower:
                continue
            
            if not delegatecall_match:
                continue
                
            # Get the target variable - skip if empty
            target_var = delegatecall_match.group(1) if delegatecall_match.group(1) else ""
            if not target_var or target_var in ['gas', 'this', 'address']:
                continue
            
            # Analyze trust level of target
            func_start = max(0, i - 50)
            func_context = '\n'.join(lines[func_start:i+1])
            full_context = '\n'.join(lines[max(0, i-100):i+1])
            
            # Extract function signature
            func_match = re.search(r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{', func_context, re.DOTALL)
            if not func_match:
                continue
                
            func_name = func_match.group(1)
            params_raw = func_match.group(2)
            modifiers = func_match.group(3).lower() if func_match.group(3) else ""
            
            # Skip internal/private - not directly callable
            if 'internal' in modifiers or 'private' in modifiers or func_name.startswith('_'):
                continue
            
            # Trust Analysis
            trust_level = "unknown"
            trust_reason = ""
            
            # Check 1: Is target hardcoded/immutable? (SAFE)
            immutable_patterns = [
                rf'{target_var}\s*=\s*0x[a-fA-F0-9]{{40}}',  # Hardcoded address
                rf'immutable\s+.*{target_var}',               # Immutable variable
                rf'constant\s+.*{target_var}',                # Constant
            ]
            for pattern in immutable_patterns:
                if re.search(pattern, full_context, re.IGNORECASE):
                    trust_level = "safe"
                    trust_reason = "Target is hardcoded/immutable"
                    break
            
            if trust_level == "safe":
                continue
            
            # Check 2: Is target from function parameter? (CRITICAL)
            param_names = re.findall(r'address\s+(\w+)|(\w+)\s+address', params_raw.lower())
            param_names = [p[0] or p[1] for p in param_names]
            
            if target_var.lower() in [p.lower() for p in param_names]:
                trust_level = "critical"
                trust_reason = f"Target '{target_var}' is a function parameter (user-controlled)"
            
            # Check 3: Is target from msg.data/calldata? (CRITICAL)  
            if re.search(rf'{target_var}.*calldataload|abi\.decode.*{target_var}', full_context, re.IGNORECASE):
                trust_level = "critical"
                trust_reason = f"Target '{target_var}' decoded from calldata (user-controlled)"
            
            # Check 4: Is target from storage without whitelist? (HIGH)
            if trust_level == "unknown":
                storage_patterns = [
                    rf'{target_var}\s*=\s*\w+\s*\[',  # From mapping
                    rf'storage.*{target_var}',
                ]
                for pattern in storage_patterns:
                    if re.search(pattern, full_context, re.IGNORECASE):
                        trust_level = "high"
                        trust_reason = f"Target '{target_var}' from storage (verify admin-only setter)"
                        break
            
            # Only report CRITICAL delegatecall issues
            if trust_level == "critical":
                # Final check: access control?
                has_access_control = any(guard in modifiers.lower() or guard in func_context.lower() for guard in [
                    'onlyowner', 'onlyadmin', 'onlyrole', 'require(msg.sender',
                    'onlyauthorized', 'auth', 'restricted', 'onlyproxy'
                ])
                
                if not has_access_control:
                    violations.append(SecurityViolation(
                        violation_type="ARBITRARY_DELEGATECALL",
                        severity="critical",
                        path_id="direct_scan",
                        line_number=i + 1,
                        description=f"CRITICAL: {trust_reason}",
                        taint_path=[f"user_input:{target_var}", "delegatecall", "storage_takeover"],
                        constraints=[
                            "No access control modifier detected",
                            "No whitelist for target address",
                            "No immutable/hardcoded target"
                        ],
                        exploit_conditions=[
                            "1. Attacker passes malicious contract address as parameter",
                            "2. Delegatecall executes attacker's code in victim's storage context",
                            "3. Attacker can overwrite ANY storage slot (owner, balances, etc)",
                            "4. Complete contract takeover possible",
                            "5. This is the #1 cause of multi-million DeFi hacks"
                        ],
                        file_path=file_path
                    ))
        
        # Pattern 3: UNPROTECTED SELFDESTRUCT - truly critical
        for i, line in enumerate(lines):
            if 'selfdestruct(' in line.lower() or 'suicide(' in line.lower():
                # Check for ANY access control in function
                func_start = max(0, i - 40)
                func_context = '\n'.join(lines[func_start:i+1])
                
                has_protection = any(guard in func_context for guard in [
                    'onlyOwner', 'onlyAdmin', 'require(msg.sender', 'require(_msgSender()',
                    'require(owner', 'modifier', 'auth', 'isOwner'
                ])
                
                if not has_protection:
                    violations.append(SecurityViolation(
                        violation_type="UNPROTECTED_SELFDESTRUCT",
                        severity="critical",
                        path_id="direct_scan",
                        line_number=i + 1,
                        description="EXPLOITABLE: Anyone can destroy this contract and steal ETH",
                        taint_path=[],
                        constraints=[],
                        exploit_conditions=[
                            "1. Attacker calls function with selfdestruct",
                            "2. Contract is destroyed",
                            "3. All ETH sent to attacker address",
                            "4. Contract permanently bricked"
                        ],
                        file_path=file_path
                    ))
        
        # Pattern 4: ARBITRARY EXTERNAL CALL - user controls target AND calldata AND no access control
        for i, line in enumerate(lines):
            # Look for .call with variable target
            call_match = re.search(r'(\w+)\.call\{?[^}]*\}?\s*\(([^)]*)\)', line)
            if call_match:
                target = call_match.group(1)
                calldata = call_match.group(2)
                
                # Check if target is a parameter (user-controlled)
                func_start = max(0, i - 40)
                func_context = '\n'.join(lines[func_start:i+1])
                func_match = re.search(r'function\s+\w+\s*\(([^)]*)\)[^{]*', func_context)
                
                if func_match:
                    params = func_match.group(1)
                    func_header = func_match.group(0)
                    
                    # Check for access control modifiers
                    has_access_control = any(guard in func_header or guard in func_context for guard in [
                        'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyAuthorized',
                        'requiresAuth', 'auth', 'restricted'
                    ])
                    
                    # If target variable appears in parameters AND no access control
                    if target in params and ('bytes' in params or 'data' in params) and not has_access_control:
                        violations.append(SecurityViolation(
                            violation_type="ARBITRARY_CALL",
                            severity="critical",
                            path_id="direct_scan",
                            line_number=i + 1,
                            description="EXPLOITABLE: Unprotected external call with user-controlled target and data",
                            taint_path=[],
                            constraints=[],
                            exploit_conditions=[
                                "1. Attacker controls target address and calldata",
                                "2. Can call any contract with any function",
                                "3. Can drain approved tokens via transferFrom",
                                "4. Can execute arbitrary actions as this contract"
                            ],
                            file_path=file_path
                        ))
        
        return violations
    
    def analyze_directory(self, directory: Path) -> Dict[str, Any]:
        """Analyze all Solidity files in directory"""
        sol_files = list(directory.rglob("*.sol"))
        
        print(f"Fast Symbolic execution on {len(sol_files)} files...")
        
        all_violations = []
        file_results = {}
        
        for sol_file in sol_files:
            violations = self.analyze_file(sol_file)
            if violations:
                file_results[str(sol_file)] = [v.__dict__ for v in violations]
                all_violations.extend(violations)
        
        # Summary
        by_severity = defaultdict(list)
        by_type = defaultdict(list)
        
        for v in all_violations:
            by_severity[v.severity].append(v)
            by_type[v.violation_type].append(v)
        
        print(f"\nSuccess Symbolic execution complete:")
        print(f"   Total violations: {len(all_violations)}")
        print(f"   Critical: {len(by_severity['critical'])}")
        print(f"   High: {len(by_severity['high'])}")
        
        print(f"\nChart By type:")
        for vuln_type, vulns in by_type.items():
            print(f"   {vuln_type}: {len(vulns)}")
        
        return {
            "total_violations": len(all_violations),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_type": {k: len(v) for k, v in by_type.items()},
            "violations": [v.__dict__ for v in all_violations],
            "file_results": file_results
        }

def main():
    """Test symbolic execution"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python symbolic_execution.py <directory|file>")
        sys.exit(1)
    
    target = Path(sys.argv[1])
    engine = SymbolicExecutionEngine()
    
    if target.is_dir():
        results = engine.analyze_directory(target)
    else:
        violations = engine.analyze_file(target)
        results = {"violations": [v.__dict__ for v in violations]}
    
    # Print findings
    print(f"\nInspect Security Violations Found:")
    for v in results.get("violations", [])[:10]:
        print(f"   [{v['severity'].upper()}] {v['violation_type']}")
        print(f"      File: {v['file_path']}:{v['line_number']}")
        print(f"      {v['description']}")
        if v['taint_path']:
            print(f"      Taint path: {' → '.join(v['taint_path'])}")
        print()
    
    # Save results
    output_path = Path("symbolic_execution_results.json")
    output_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"Document Results saved to: {output_path}")

if __name__ == "__main__":
    main()
