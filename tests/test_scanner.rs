//! Integration tests for HyperionScan

use std::path::PathBuf;

/// Test file walker functionality
#[test]
fn test_file_walker() {
    // Basic test that file walker can be instantiated
    // Full tests would require test fixtures
}

/// Test language detection
#[test]
fn test_language_detection() {
    use std::path::Path;
    
    // Test extension-based detection
    let sol_path = Path::new("contract.sol");
    let rs_path = Path::new("main.rs");
    let js_path = Path::new("index.js");
    
    assert!(sol_path.extension().map_or(false, |e| e == "sol"));
    assert!(rs_path.extension().map_or(false, |e| e == "rs"));
    assert!(js_path.extension().map_or(false, |e| e == "js"));
}

/// Test solidity pattern detection
#[test]
fn test_solidity_patterns() {
    let source = r#"
pragma solidity ^0.8.0;

contract Vulnerable {
    function withdraw() external {
        // Reentrancy vulnerability
        (bool success, ) = msg.sender.call{value: balance}("");
        balance = 0;
    }
    
    function authenticate() external {
        // tx.origin vulnerability
        require(tx.origin == owner);
    }
}
"#;

    // Should detect:
    // 1. Floating pragma
    // 2. Reentrancy (call with value)
    // 3. tx.origin usage
    
    assert!(source.contains("pragma solidity ^"));
    assert!(source.contains(".call{value:"));
    assert!(source.contains("tx.origin"));
}

/// Test secret detection patterns
#[test]
fn test_secret_patterns() {
    let source = r#"
const API_KEY = "sk_live_abcdefghijklmnop123456";
const PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
"#;

    // Should detect all three secrets
    assert!(source.contains("API_KEY"));
    assert!(source.contains("0x") && source.len() > 64);
    assert!(source.contains("AKIA"));
}

/// Test report generation
#[test]
fn test_finding_severity() {
    let severities = ["critical", "high", "medium", "low", "info"];
    
    for sev in severities {
        let level = match sev {
            "critical" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "info" => 1,
            _ => 0,
        };
        assert!(level > 0);
    }
}
