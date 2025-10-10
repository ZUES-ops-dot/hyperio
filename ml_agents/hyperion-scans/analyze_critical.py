#!/usr/bin/env python3
"""
Focused analysis on critical vulnerabilities only.
Builds mini knowledge graph + traces exploit paths.
"""
import json
import time
from pathlib import Path
from collections import defaultdict

# Critical contracts from scan results
CRITICAL_CONTRACTS = [
    "DefaultTimeLock.sol",  # REENTRANCY_LOOP
    "iETH.sol",             # MISSING_ACCESS_CONTROL  
    "iETHV2.sol",           # MISSING_ACCESS_CONTROL
]

def main():
    print("=" * 60)
    print("Target FOCUSED CRITICAL VULNERABILITY ANALYSIS")
    print("=" * 60)
    
    start = time.time()
    target_dir = Path("../test-contracts/src")
    
    # Find critical contract files
    critical_files = []
    for name in CRITICAL_CONTRACTS:
        found = list(target_dir.rglob(name))
        if found:
            critical_files.append(found[0])
            print(f"   Success Found: {name}")
        else:
            print(f"   Failure Not found: {name}")
    
    if not critical_files:
        print("No critical contracts found!")
        return
    
    # =========================================================
    # Stage 1: Deep symbolic analysis on critical contracts
    # =========================================================
    print(f"\nFast Stage 1: Deep Symbolic Analysis")
    print("-" * 40)
    
    from symbolic_execution import SymbolicExecutionEngine
    se = SymbolicExecutionEngine()
    
    all_violations = []
    for f in critical_files:
        print(f"\n   Document {f.name}")
        violations = se.analyze_file(f)
        
        for v in violations:
            severity_icon = "Critical" if v.severity == "critical" else "High"
            print(f"      {severity_icon} [{v.severity.upper()}] {v.violation_type}")
            print(f"         Line {v.line_number}: {v.description[:60]}...")
            if v.exploit_conditions:
                print(f"         Exploit: {v.exploit_conditions[0]}")
        
        all_violations.extend(violations)
    
    # =========================================================
    # Stage 2: Mini Knowledge Graph for critical contracts
    # =========================================================
    print(f"\nChart Stage 2: Mini Knowledge Graph")
    print("-" * 40)
    
    from knowledge_graph import KnowledgeGraph
    kg = KnowledgeGraph()
    
    # Parse only critical files
    for f in critical_files:
        nodes = kg.parse_solidity_file(f)
        print(f"   {f.name}: {len(nodes)} nodes")
    
    print(f"\n   Graph Stats:")
    print(f"   ├─ Contracts: {len(kg.contracts)}")
    print(f"   ├─ Functions: {len(kg.functions)}")
    print(f"   ├─ Variables: {len(kg.variables)}")
    print(f"   ├─ Entry Points: {len(kg.entry_points)}")
    print(f"   └─ Sensitive Ops: {len(kg.sensitive_operations)}")
    
    # =========================================================
    # Stage 3: Trace exploit paths
    # =========================================================
    print(f"\nInspect Stage 3: Exploit Path Tracing")
    print("-" * 40)
    
    # For each critical finding, trace the call path
    for v in all_violations:
        if v.severity == "critical":
            print(f"\n   Target {v.violation_type} @ {Path(v.file_path).name}:{v.line_number}")
            
            # Find entry points that can reach this
            file_name = Path(v.file_path).name
            reachable_funcs = []
            
            for func_id, func in kg.functions.items():
                if file_name in func.file_path:
                    # Check if vulnerability line is within function
                    if func.line_start <= v.line_number <= func.line_end:
                        reachable_funcs.append(func)
                        print(f"      Location In function: {func.name}()")
                        print(f"         Visibility: {func.visibility}")
                        print(f"         Modifiers: {func.modifiers or 'none'}")
                        print(f"         Payable: {func.is_payable}")
                        
                        # Is this an entry point?
                        if func.visibility in ['public', 'external']:
                            print(f"         Warning  DIRECTLY CALLABLE - Entry point!")
    
    # =========================================================
    # Stage 4: Generate exploit summary
    # =========================================================
    print(f"\nCritical Stage 4: Exploit Summary")
    print("-" * 40)
    
    critical_count = sum(1 for v in all_violations if v.severity == "critical")
    high_count = sum(1 for v in all_violations if v.severity == "high")
    
    print(f"""
   Critical Vulnerabilities: {critical_count}
   High Vulnerabilities: {high_count}
   
   Analyzed Contracts: {len(critical_files)}
   Total Functions: {len(kg.functions)}
   Entry Points: {len(kg.entry_points)}
""")
    
    # Group by type
    by_type = defaultdict(list)
    for v in all_violations:
        by_type[v.violation_type].append(v)
    
    print("   By Vulnerability Type:")
    for vtype, vulns in sorted(by_type.items()):
        crit = sum(1 for v in vulns if v.severity == "critical")
        high = sum(1 for v in vulns if v.severity == "high")
        print(f"   ├─ {vtype}: {crit} critical, {high} high")
    
    # =========================================================
    # Save detailed report
    # =========================================================
    report = {
        "analysis_time": time.time() - start,
        "contracts_analyzed": [str(f) for f in critical_files],
        "summary": {
            "critical": critical_count,
            "high": high_count,
            "functions": len(kg.functions),
            "entry_points": len(kg.entry_points)
        },
        "vulnerabilities": [
            {
                "type": v.violation_type,
                "severity": v.severity,
                "file": Path(v.file_path).name,
                "line": v.line_number,
                "description": v.description,
                "exploit_conditions": v.exploit_conditions
            }
            for v in all_violations
        ],
        "entry_points": [
            {
                "function": kg.functions[ep].name if ep in kg.functions else ep,
                "file": kg.functions[ep].file_path if ep in kg.functions else "unknown"
            }
            for ep in kg.entry_points[:20]  # Top 20
        ]
    }
    
    report_path = Path("critical_analysis_report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str))
    
    print(f"\n{'='*60}")
    print(f"Success Analysis complete in {time.time()-start:.1f}s")
    print(f"Document Report: {report_path}")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
