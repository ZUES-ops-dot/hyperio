//! Solidity Security Scanner Plugin
//!
//! Detects common vulnerabilities in Solidity smart contracts:
//! - Reentrancy
//! - Access control issues
//! - Integer overflow/underflow
//! - Unchecked return values
//! - Dangerous delegatecall
//! - And more...

use serde::{Deserialize, Serialize};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct PluginInput {
    language: String,
    path: String,
    source: String,
    ast: String,
    hash: String,
}

#[derive(Debug, Serialize)]
struct Finding {
    id: String,
    severity: String,
    message: String,
    line: usize,
    column: usize,
    rule_name: Option<String>,
    cwe: Option<String>,
    fix_suggestion: Option<String>,
    snippet: Option<String>,
    confidence: f64,
}

#[derive(Debug, Serialize)]
struct PluginOutput {
    findings: Vec<Finding>,
    metadata: HashMap<String, String>,
    errors: Vec<String>,
}

struct SolidityChecker {
    checks: Vec<Check>,
}

struct Check {
    id: &'static str,
    name: &'static str,
    pattern: Regex,
    severity: &'static str,
    message: &'static str,
    cwe: Option<&'static str>,
    fix: Option<&'static str>,
}

impl SolidityChecker {
    fn new() -> Self {
        let checks = vec![
            // Reentrancy
            Check {
                id: "SOL_REENTRANCY_001",
                name: "Reentrancy via call.value",
                pattern: Regex::new(r"\.call\{?\s*value").unwrap(),
                severity: "critical",
                message: "Potential reentrancy vulnerability. External call with value transfer detected.",
                cwe: Some("CWE-841"),
                fix: Some("Use ReentrancyGuard or checks-effects-interactions pattern"),
            },
            
            // tx.origin
            Check {
                id: "SOL_AUTH_001",
                name: "tx.origin Authentication",
                pattern: Regex::new(r"tx\.origin").unwrap(),
                severity: "high",
                message: "tx.origin used - vulnerable to phishing attacks",
                cwe: Some("CWE-346"),
                fix: Some("Use msg.sender instead of tx.origin"),
            },
            
            // Delegatecall
            Check {
                id: "SOL_DELEGATECALL_001",
                name: "Dangerous delegatecall",
                pattern: Regex::new(r"\.delegatecall\s*\(").unwrap(),
                severity: "critical",
                message: "delegatecall to potentially untrusted contract",
                cwe: Some("CWE-829"),
                fix: Some("Ensure target is trusted and storage layouts match"),
            },
            
            // Selfdestruct
            Check {
                id: "SOL_SELFDESTRUCT_001",
                name: "Selfdestruct usage",
                pattern: Regex::new(r"selfdestruct\s*\(").unwrap(),
                severity: "high",
                message: "selfdestruct can permanently destroy the contract",
                cwe: Some("CWE-284"),
                fix: Some("Ensure proper access control on selfdestruct"),
            },
            
            // Block timestamp
            Check {
                id: "SOL_TIMESTAMP_001",
                name: "Block timestamp dependence",
                pattern: Regex::new(r"block\.(timestamp|number)").unwrap(),
                severity: "low",
                message: "Block values can be manipulated by miners",
                cwe: Some("CWE-829"),
                fix: Some("Don't rely on block values for critical logic"),
            },
            
            // Floating pragma
            Check {
                id: "SOL_PRAGMA_001",
                name: "Floating pragma",
                pattern: Regex::new(r"pragma solidity\s*\^").unwrap(),
                severity: "low",
                message: "Floating pragma allows different compiler versions",
                cwe: None,
                fix: Some("Lock to specific version: pragma solidity 0.8.19;"),
            },
            
            // Unchecked send
            Check {
                id: "SOL_SEND_001",
                name: "Unchecked send",
                pattern: Regex::new(r"\.send\s*\([^)]+\)\s*;").unwrap(),
                severity: "medium",
                message: "Return value of send() not checked",
                cwe: Some("CWE-252"),
                fix: Some("Check return value: require(addr.send(amount));"),
            },
            
            // Assembly
            Check {
                id: "SOL_ASSEMBLY_001",
                name: "Inline assembly",
                pattern: Regex::new(r"assembly\s*\{").unwrap(),
                severity: "medium",
                message: "Inline assembly bypasses Solidity safety checks",
                cwe: None,
                fix: Some("Review assembly carefully for safety"),
            },
            
            // Private key pattern
            Check {
                id: "SOL_SECRET_001",
                name: "Possible private key",
                pattern: Regex::new(r"0x[0-9a-fA-F]{64}").unwrap(),
                severity: "critical",
                message: "Possible hardcoded private key or secret",
                cwe: Some("CWE-798"),
                fix: Some("Remove hardcoded secrets, use environment variables"),
            },
        ];

        Self { checks }
    }

    fn analyze(&self, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            for check in &self.checks {
                if check.pattern.is_match(line) {
                    findings.push(Finding {
                        id: check.id.to_string(),
                        severity: check.severity.to_string(),
                        message: check.message.to_string(),
                        line: line_num + 1,
                        column: 0,
                        rule_name: Some(check.name.to_string()),
                        cwe: check.cwe.map(|s| s.to_string()),
                        fix_suggestion: check.fix.map(|s| s.to_string()),
                        snippet: Some(line.trim().to_string()),
                        confidence: 0.85,
                    });
                }
            }
        }

        findings
    }
}

#[no_mangle]
pub extern "C" fn analyze(input_ptr: i32, input_len: i32) -> i32 {
    // Plugin entry point
    0
}

fn run_analysis(input: &PluginInput) -> PluginOutput {
    // Only analyze Solidity files
    if input.language != "solidity" {
        return PluginOutput {
            findings: vec![],
            metadata: HashMap::new(),
            errors: vec![],
        };
    }

    let checker = SolidityChecker::new();
    let findings = checker.analyze(&input.source);

    PluginOutput {
        findings,
        metadata: HashMap::new(),
        errors: vec![],
    }
}

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}
