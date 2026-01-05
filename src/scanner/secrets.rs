//! Secret detection scanner

use anyhow::Result;
use regex::Regex;
use crate::core::SourceFile;
use crate::reports::Finding;

/// Scanner for detecting hardcoded secrets
pub struct SecretScanner {
    patterns: Vec<SecretPattern>,
}

struct SecretPattern {
    id: String,
    name: String,
    regex: Regex,
    severity: String,
    message: String,
}

impl SecretScanner {
    /// Create a new secret scanner
    pub fn new() -> Self {
        let patterns = vec![
            // Private Keys
            SecretPattern {
                id: "SECRET_PRIVKEY_001".to_string(),
                name: "Ethereum Private Key".to_string(),
                regex: Regex::new(r#"(?i)(private[_-]?key|privkey|secret[_-]?key)\s*[:=]\s*['""]?([0-9a-fA-F]{64})['""]?"#).unwrap(),
                severity: "critical".to_string(),
                message: "Hardcoded Ethereum private key detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_PRIVKEY_002".to_string(),
                name: "Hex Private Key Pattern".to_string(),
                regex: Regex::new(r#"0x[0-9a-fA-F]{64}"#).unwrap(),
                severity: "high".to_string(),
                message: "Possible hardcoded 256-bit private key".to_string(),
            },

            // Mnemonics
            SecretPattern {
                id: "SECRET_MNEMONIC_001".to_string(),
                name: "BIP39 Mnemonic".to_string(),
                regex: Regex::new(r#"(?i)(mnemonic|seed[_-]?phrase)\s*[:=]\s*['""]([a-z]+\s+){11,23}[a-z]+['""]"#).unwrap(),
                severity: "critical".to_string(),
                message: "Hardcoded BIP39 mnemonic phrase detected".to_string(),
            },

            // API Keys
            SecretPattern {
                id: "SECRET_API_001".to_string(),
                name: "API Key".to_string(),
                regex: Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['""]?([a-zA-Z0-9_-]{20,})['""]?"#).unwrap(),
                severity: "high".to_string(),
                message: "Hardcoded API key detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_API_002".to_string(),
                name: "Infura API Key".to_string(),
                regex: Regex::new(r#"(?i)infura[^\s]*[:=]\s*['""]?([a-f0-9]{32})['""]?"#).unwrap(),
                severity: "high".to_string(),
                message: "Hardcoded Infura API key detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_API_003".to_string(),
                name: "Alchemy API Key".to_string(),
                regex: Regex::new(r#"(?i)alchemy[^\s]*[:=]\s*['""]?([a-zA-Z0-9_-]{32,})['""]?"#).unwrap(),
                severity: "high".to_string(),
                message: "Hardcoded Alchemy API key detected".to_string(),
            },

            // AWS
            SecretPattern {
                id: "SECRET_AWS_001".to_string(),
                name: "AWS Access Key".to_string(),
                regex: Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
                severity: "critical".to_string(),
                message: "AWS Access Key ID detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_AWS_002".to_string(),
                name: "AWS Secret Key".to_string(),
                regex: Regex::new(r#"(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['""]?([a-zA-Z0-9/+=]{40})['""]?"#).unwrap(),
                severity: "critical".to_string(),
                message: "AWS Secret Access Key detected".to_string(),
            },

            // Generic Secrets
            SecretPattern {
                id: "SECRET_GENERIC_001".to_string(),
                name: "Generic Secret".to_string(),
                regex: Regex::new(r#"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['""]([^'""]{8,})['""]"#).unwrap(),
                severity: "high".to_string(),
                message: "Hardcoded secret or password detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_GENERIC_002".to_string(),
                name: "Bearer Token".to_string(),
                regex: Regex::new(r#"(?i)(bearer|authorization)\s*[:=]\s*['""]([a-zA-Z0-9_.-]{20,})['""]"#).unwrap(),
                severity: "high".to_string(),
                message: "Hardcoded bearer/authorization token detected".to_string(),
            },

            // RPC URLs with embedded credentials
            SecretPattern {
                id: "SECRET_RPC_001".to_string(),
                name: "RPC URL with Key".to_string(),
                regex: Regex::new(r#"https?://[^/]*@[^/]+"#).unwrap(),
                severity: "high".to_string(),
                message: "RPC URL with embedded credentials detected".to_string(),
            },
            SecretPattern {
                id: "SECRET_RPC_002".to_string(),
                name: "Mainnet RPC with Key".to_string(),
                regex: Regex::new(r#"https://(mainnet|eth)[^'""\s]+[a-f0-9]{20,}"#).unwrap(),
                severity: "high".to_string(),
                message: "Mainnet RPC URL with API key in URL".to_string(),
            },

            // Database Connection Strings
            SecretPattern {
                id: "SECRET_DB_001".to_string(),
                name: "Database Connection String".to_string(),
                regex: Regex::new(r#"(?i)(mongodb|postgres|mysql|redis)://[^'""\s]+:[^@'""\s]+@"#).unwrap(),
                severity: "critical".to_string(),
                message: "Database connection string with credentials detected".to_string(),
            },

            // JWT
            SecretPattern {
                id: "SECRET_JWT_001".to_string(),
                name: "JWT Token".to_string(),
                regex: Regex::new(r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+"#).unwrap(),
                severity: "medium".to_string(),
                message: "JWT token detected - may contain sensitive claims".to_string(),
            },

            // GitHub
            SecretPattern {
                id: "SECRET_GITHUB_001".to_string(),
                name: "GitHub Token".to_string(),
                regex: Regex::new(r#"gh[pousr]_[0-9a-zA-Z]{36}"#).unwrap(),
                severity: "critical".to_string(),
                message: "GitHub personal access token detected".to_string(),
            },

            // SSH Private Key
            SecretPattern {
                id: "SECRET_SSH_001".to_string(),
                name: "SSH Private Key".to_string(),
                regex: Regex::new(r#"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"#).unwrap(),
                severity: "critical".to_string(),
                message: "SSH private key header detected".to_string(),
            },
        ];

        Self { patterns }
    }

    /// Scan file for secrets
    pub fn scan(&self, file: &SourceFile) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Skip binary files, lock files, and known safe files
        let path_str = file.relative_path.to_string_lossy().to_lowercase();
        if path_str.ends_with(".lock") 
            || path_str.contains("node_modules")
            || path_str.ends_with(".min.js")
            || path_str.ends_with(".map")
        {
            return Ok(findings);
        }

        for (line_num, line) in file.content.lines().enumerate() {
            // Skip comment-only lines that might be examples
            let trimmed = line.trim();
            if trimmed.starts_with("//") && trimmed.contains("example") {
                continue;
            }

            for pattern in &self.patterns {
                if pattern.regex.is_match(line) {
                    // Mask the actual secret in the snippet
                    let masked_snippet = self.mask_secret(line);
                    
                    findings.push(Finding {
                        id: pattern.id.clone(),
                        severity: pattern.severity.clone(),
                        message: pattern.message.clone(),
                        path: file.relative_path.to_string_lossy().to_string(),
                        line: line_num + 1,
                        column: 0,
                        snippet: Some(masked_snippet),
                        rule_name: pattern.name.clone(),
                        category: "secrets".to_string(),
                        confidence: 0.9,
                        cwe: Some("CWE-798".to_string()),
                        fix_suggestion: Some("Remove hardcoded secret and use environment variables or a secrets manager".to_string()),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Mask sensitive data in snippet
    fn mask_secret(&self, line: &str) -> String {
        // Replace long hex strings
        let re = Regex::new(r"[0-9a-fA-F]{16,}").unwrap();
        let result = re.replace_all(line, "****REDACTED****");
        
        // Replace quoted strings that look like secrets
        let re2 = Regex::new(r#"['"""][^'""]{20,}['"""]"#).unwrap();
        re2.replace_all(&result, "\"****REDACTED****\"").to_string()
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}
