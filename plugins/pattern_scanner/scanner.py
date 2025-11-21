#!/usr/bin/env python3
"""
Pattern Scanner - CLI Plugin for HyperionScan

This is a simple CLI-based plugin that receives JSON input on stdin
and outputs JSON findings on stdout.

Input format:
{
    "language": "solidity",
    "path": "contracts/Token.sol",
    "source": "...",
    "ast": "...",
    "hash": "..."
}

Output format:
{
    "findings": [...],
    "metadata": {},
    "errors": []
}
"""

import sys
import json
import re
from typing import List, Dict, Any

# Security patterns to detect
PATTERNS = [
    {
        "id": "PAT_TODO_001",
        "name": "TODO Comment",
        "pattern": r"(?i)(TODO|FIXME|HACK|XXX|BUG)[\s:]+(.+)",
        "severity": "info",
        "message": "TODO/FIXME comment found - may indicate incomplete implementation",
    },
    {
        "id": "PAT_CONSOLE_001",
        "name": "Console Log",
        "pattern": r"console\.(log|debug|info|warn|error)\s*\(",
        "severity": "low",
        "message": "Console log statement found - remove before production",
        "languages": ["javascript", "typescript"],
    },
    {
        "id": "PAT_EVAL_001",
        "name": "Dangerous Eval",
        "pattern": r"\beval\s*\(",
        "severity": "high",
        "message": "Use of eval() is dangerous and can lead to code injection",
        "cwe": "CWE-95",
    },
    {
        "id": "PAT_HARDCODED_IP_001",
        "name": "Hardcoded IP",
        "pattern": r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "severity": "low",
        "message": "Hardcoded IP address found",
    },
    {
        "id": "PAT_SQL_001",
        "name": "SQL Injection Risk",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*(\$|var|param|input|request)",
        "severity": "critical",
        "message": "Potential SQL injection - use parameterized queries",
        "cwe": "CWE-89",
    },
    {
        "id": "PAT_EXEC_001",
        "name": "Command Execution",
        "pattern": r"(exec|system|popen|subprocess\.call|os\.system|child_process)\s*\(",
        "severity": "high",
        "message": "Command execution detected - ensure input is sanitized",
        "cwe": "CWE-78",
    },
    {
        "id": "PAT_WEAK_RANDOM_001",
        "name": "Weak Random",
        "pattern": r"Math\.random\s*\(\)|random\.random\s*\(",
        "severity": "medium",
        "message": "Weak random number generator - not suitable for cryptography",
        "cwe": "CWE-338",
    },
    {
        "id": "PAT_DEBUG_001",
        "name": "Debug Statement",
        "pattern": r"(debugger|pdb\.set_trace|breakpoint\(\))",
        "severity": "low",
        "message": "Debug statement found - remove before production",
    },
]


def analyze(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze source code and return findings."""
    findings = []
    errors = []
    
    try:
        source = input_data.get("source", "")
        path = input_data.get("path", "")
        language = input_data.get("language", "").lower()
        
        lines = source.split("\n")
        
        for line_num, line in enumerate(lines, 1):
            for pattern in PATTERNS:
                # Check language filter
                allowed_langs = pattern.get("languages", [])
                if allowed_langs and language not in allowed_langs:
                    continue
                
                # Check pattern match
                regex = re.compile(pattern["pattern"])
                if regex.search(line):
                    findings.append({
                        "id": pattern["id"],
                        "severity": pattern["severity"],
                        "message": pattern["message"],
                        "line": line_num,
                        "column": 0,
                        "rule_name": pattern["name"],
                        "cwe": pattern.get("cwe"),
                        "fix_suggestion": pattern.get("fix"),
                        "snippet": line.strip()[:100],
                        "confidence": 0.8,
                    })
    except Exception as e:
        errors.append(f"Analysis error: {str(e)}")
    
    return {
        "findings": findings,
        "metadata": {
            "plugin": "pattern_scanner",
            "version": "0.1.0",
        },
        "errors": errors,
    }


def main():
    """Main entry point - read JSON from stdin, write results to stdout."""
    try:
        # Read input from stdin
        input_text = sys.stdin.read()
        
        if not input_text.strip():
            print(json.dumps({"findings": [], "metadata": {}, "errors": ["No input received"]}))
            return
        
        input_data = json.loads(input_text)
        
        # Run analysis
        result = analyze(input_data)
        
        # Output result as JSON
        print(json.dumps(result))
        
    except json.JSONDecodeError as e:
        print(json.dumps({
            "findings": [],
            "metadata": {},
            "errors": [f"Invalid JSON input: {str(e)}"]
        }))
    except Exception as e:
        print(json.dumps({
            "findings": [],
            "metadata": {},
            "errors": [f"Plugin error: {str(e)}"]
        }))


if __name__ == "__main__":
    main()
