#!/usr/bin/env python3
"""Run critical vulnerability scan"""
from symbolic_execution import SymbolicExecutionEngine
from pathlib import Path

se = SymbolicExecutionEngine()
results = se.analyze_directory(Path("../test-contracts/src"))

# Filter out mock files from results
filtered_violations = [
    v for v in results['violations']
    if 'mock' not in v['file_path'].lower()
]

# Recalculate counts
critical_count = sum(1 for v in filtered_violations if v['severity'] == 'critical')
high_count = sum(1 for v in filtered_violations if v['severity'] == 'high')

print(f"\n{'='*50}")
print("CRITICAL VULNERABILITY SCAN RESULTS")
print(f"{'='*50}")
print(f"Total (excluding mocks): {len(filtered_violations)}")
print(f"Critical: {critical_count}")
print(f"High: {high_count}")

# Count by type
from collections import Counter
type_counts = Counter(v['violation_type'] for v in filtered_violations)
print(f"\nBy Type:")
for vtype, count in type_counts.items():
    print(f"  {vtype}: {count}")

print(f"\n{'='*50}")
print("CRITICAL FINDINGS (excluding mocks):")
print(f"{'='*50}")
for v in filtered_violations:
    if v['severity'] == 'critical':
        print(f"\n[CRITICAL] {v['violation_type']}")
        print(f"  File: {v['file_path']}")
        print(f"  Line: {v['line_number']}")
        print(f"  {v['description']}")
        if v.get('taint_path'):
            print(f"  Taint: {' -> '.join(v['taint_path'])}")
        if v.get('exploit_conditions'):
            print(f"  Exploit: {v['exploit_conditions'][0]}")
