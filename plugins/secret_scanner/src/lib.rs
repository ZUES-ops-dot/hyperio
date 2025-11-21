//! Secret Scanner Plugin
//!
//! Detects hardcoded secrets, API keys, and credentials:
//! - Private keys (Ethereum, SSH)
//! - API keys (AWS, Infura, Alchemy)
//! - Passwords and tokens
//! - Database connection strings
//! - Mnemonics and seed phrases

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

struct SecretPattern {
    id: &'static str,
    name: &'static str,
    pattern: Regex,
    severity: &'static str,
    message: &'static str,
}

struct SecretChecker {
    patterns: Vec<SecretPattern>,
}

impl SecretChecker {
    fn new() -> Self {
        let patterns = vec![
            // Ethereum private key
            SecretPattern {
                id: "SECRET_ETH_KEY_001",
                name: "Ethereum Private Key",
                pattern: Regex::new(r"(?i)(private[_-]?key|privkey)\s*[:=]\s*['\"]?0x[0-9a-fA-F]{64}").unwrap(),
                severity: "critical",
                message: "Hardcoded Ethereum private key detected",
            },
            
            // Generic hex key
            SecretPattern {
                id: "SECRET_HEX_KEY_001",
                name: "256-bit Hex Key",
                pattern: Regex::new(r"0x[0-9a-fA-F]{64}").unwrap(),
                severity: "high",
                message: "Possible hardcoded 256-bit private key",
            },
            
            // AWS Access Key
            SecretPattern {
                id: "SECRET_AWS_001",
                name: "AWS Access Key",
                pattern: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                severity: "critical",
                message: "AWS Access Key ID detected",
            },
            
            // AWS Secret
            SecretPattern {
                id: "SECRET_AWS_002",
                name: "AWS Secret Key",
                pattern: Regex::new(r"(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9/+=]{40}").unwrap(),
                severity: "critical",
                message: "AWS Secret Access Key detected",
            },
            
            // Generic API Key
            SecretPattern {
                id: "SECRET_API_001",
                name: "API Key",
                pattern: Regex::new(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}").unwrap(),
                severity: "high",
                message: "Hardcoded API key detected",
            },
            
            // Infura
            SecretPattern {
                id: "SECRET_INFURA_001",
                name: "Infura API Key",
                pattern: Regex::new(r"(?i)infura[^\s]*[:=]\s*['\"]?[a-f0-9]{32}").unwrap(),
                severity: "high",
                message: "Hardcoded Infura API key detected",
            },
            
            // Alchemy
            SecretPattern {
                id: "SECRET_ALCHEMY_001",
                name: "Alchemy API Key",
                pattern: Regex::new(r"(?i)alchemy[^\s]*[:=]\s*['\"]?[a-zA-Z0-9_-]{32,}").unwrap(),
                severity: "high",
                message: "Hardcoded Alchemy API key detected",
            },
            
            // GitHub Token
            SecretPattern {
                id: "SECRET_GITHUB_001",
                name: "GitHub Token",
                pattern: Regex::new(r"gh[pousr]_[0-9a-zA-Z]{36}").unwrap(),
                severity: "critical",
                message: "GitHub personal access token detected",
            },
            
            // Generic password
            SecretPattern {
                id: "SECRET_PASSWORD_001",
                name: "Hardcoded Password",
                pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['""][^'""]{8,}['""]"#).unwrap(),
                severity: "high",
                message: "Hardcoded password detected",
            },
            
            // Database connection string
            SecretPattern {
                id: "SECRET_DB_001",
                name: "Database Connection String",
                pattern: Regex::new(r"(?i)(mongodb|postgres|mysql|redis)://[^\s]+:[^@\s]+@").unwrap(),
                severity: "critical",
                message: "Database connection string with credentials detected",
            },
            
            // JWT Token
            SecretPattern {
                id: "SECRET_JWT_001",
                name: "JWT Token",
                pattern: Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+").unwrap(),
                severity: "medium",
                message: "JWT token detected - may contain sensitive claims",
            },
            
            // SSH Private Key
            SecretPattern {
                id: "SECRET_SSH_001",
                name: "SSH Private Key",
                pattern: Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
                severity: "critical",
                message: "SSH private key header detected",
            },
            
            // Mnemonic phrase
            SecretPattern {
                id: "SECRET_MNEMONIC_001",
                name: "BIP39 Mnemonic",
                pattern: Regex::new(r#"(?i)(mnemonic|seed[_-]?phrase)\s*[:=]\s*['""]([a-z]+\s+){11,23}[a-z]+['""]"#).unwrap(),
                severity: "critical",
                message: "Hardcoded BIP39 mnemonic phrase detected",
            },
        ];

        Self { patterns }
    }

    fn analyze(&self, source: &str, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip common false-positive paths
        let path_lower = path.to_lowercase();
        if path_lower.contains("node_modules") 
            || path_lower.ends_with(".lock")
            || path_lower.ends_with(".min.js")
            || path_lower.contains("test")
            || path_lower.contains("mock")
        {
            return findings;
        }

        for (line_num, line) in source.lines().enumerate() {
            // Skip comment lines with "example" (likely documentation)
            let trimmed = line.trim();
            if (trimmed.starts_with("//") || trimmed.starts_with("#") || trimmed.starts_with("*"))
                && trimmed.to_lowercase().contains("example")
            {
                continue;
            }

            for pattern in &self.patterns {
                if pattern.pattern.is_match(line) {
                    // Mask the secret in the snippet
                    let masked = mask_secrets(line);
                    
                    findings.push(Finding {
                        id: pattern.id.to_string(),
                        severity: pattern.severity.to_string(),
                        message: pattern.message.to_string(),
                        line: line_num + 1,
                        column: 0,
                        rule_name: Some(pattern.name.to_string()),
                        cwe: Some("CWE-798".to_string()),
                        fix_suggestion: Some("Remove hardcoded secret and use environment variables or a secrets manager".to_string()),
                        snippet: Some(masked),
                        confidence: 0.9,
                    });
                }
            }
        }

        findings
    }
}

fn mask_secrets(line: &str) -> String {
    // Mask hex strings
    let re1 = Regex::new(r"[0-9a-fA-F]{16,}").unwrap();
    let result = re1.replace_all(line, "****REDACTED****");
    
    // Mask quoted strings that look like secrets
    let re2 = Regex::new(r#"['""][^'""]{20,}['""]"#).unwrap();
    re2.replace_all(&result, "\"****REDACTED****\"").to_string()
}

#[no_mangle]
pub extern "C" fn analyze(input_ptr: i32, input_len: i32) -> i32 {
    0
}

fn run_analysis(input: &PluginInput) -> PluginOutput {
    let checker = SecretChecker::new();
    let findings = checker.analyze(&input.source, &input.path);

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
