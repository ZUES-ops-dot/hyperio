//! Rust-specific security scanner

use anyhow::Result;
use regex::Regex;
use crate::core::SourceFile;
use crate::core::AstResult;
use crate::reports::Finding;

/// Rust security scanner
pub struct RustScanner {
    patterns: Vec<RustPattern>,
}

struct RustPattern {
    id: String,
    name: String,
    regex: Regex,
    severity: String,
    message: String,
    cwe: Option<String>,
    fix: Option<String>,
}

impl RustScanner {
    /// Create a new Rust scanner
    pub fn new() -> Self {
        let patterns = vec![
            // Unsafe blocks
            RustPattern {
                id: "RUST_UNSAFE_001".to_string(),
                name: "Unsafe Block".to_string(),
                regex: Regex::new(r#"\bunsafe\s*\{"#).unwrap(),
                severity: "medium".to_string(),
                message: "Unsafe block detected - requires manual review".to_string(),
                cwe: Some("CWE-119".to_string()),
                fix: Some("Document why unsafe is needed and ensure all invariants are upheld".to_string()),
            },
            RustPattern {
                id: "RUST_UNSAFE_002".to_string(),
                name: "Unsafe Function".to_string(),
                regex: Regex::new(r#"\bunsafe\s+fn\b"#).unwrap(),
                severity: "medium".to_string(),
                message: "Unsafe function declaration".to_string(),
                cwe: Some("CWE-119".to_string()),
                fix: Some("Document safety requirements in function comments".to_string()),
            },

            // Raw pointer operations
            RustPattern {
                id: "RUST_RAW_PTR_001".to_string(),
                name: "Raw Pointer Dereference".to_string(),
                regex: Regex::new(r#"\*\s*(mut\s+)?\w+\s+as\s+\*"#).unwrap(),
                severity: "high".to_string(),
                message: "Raw pointer casting detected".to_string(),
                cwe: Some("CWE-476".to_string()),
                fix: Some("Verify pointer is valid before dereferencing".to_string()),
            },

            // Panicking code
            RustPattern {
                id: "RUST_PANIC_001".to_string(),
                name: "Explicit Panic".to_string(),
                regex: Regex::new(r#"\bpanic!\s*\("#).unwrap(),
                severity: "medium".to_string(),
                message: "Explicit panic! macro - may cause unexpected termination".to_string(),
                cwe: None,
                fix: Some("Consider using Result for recoverable errors".to_string()),
            },
            RustPattern {
                id: "RUST_PANIC_002".to_string(),
                name: "Unwrap on Option/Result".to_string(),
                regex: Regex::new(r#"\.(unwrap|expect)\s*\("#).unwrap(),
                severity: "low".to_string(),
                message: "unwrap()/expect() may panic on None/Err".to_string(),
                cwe: None,
                fix: Some("Use pattern matching or ? operator for proper error handling".to_string()),
            },
            RustPattern {
                id: "RUST_PANIC_003".to_string(),
                name: "Array Index Access".to_string(),
                regex: Regex::new(r#"\[\s*\w+\s*\]"#).unwrap(),
                severity: "info".to_string(),
                message: "Direct array indexing may panic on out-of-bounds".to_string(),
                cwe: Some("CWE-129".to_string()),
                fix: Some("Consider using .get() for bounds-checked access".to_string()),
            },

            // Transmute
            RustPattern {
                id: "RUST_TRANSMUTE_001".to_string(),
                name: "Transmute Usage".to_string(),
                regex: Regex::new(r#"std::mem::transmute"#).unwrap(),
                severity: "high".to_string(),
                message: "transmute is extremely unsafe and can cause undefined behavior".to_string(),
                cwe: Some("CWE-704".to_string()),
                fix: Some("Use safer alternatives like Into/From traits or explicit casting".to_string()),
            },

            // Memory operations
            RustPattern {
                id: "RUST_MEM_001".to_string(),
                name: "Uninitialized Memory".to_string(),
                regex: Regex::new(r#"MaybeUninit|mem::uninitialized"#).unwrap(),
                severity: "high".to_string(),
                message: "Uninitialized memory usage - ensure proper initialization".to_string(),
                cwe: Some("CWE-824".to_string()),
                fix: Some("Ensure memory is properly initialized before use".to_string()),
            },

            // FFI
            RustPattern {
                id: "RUST_FFI_001".to_string(),
                name: "FFI Declaration".to_string(),
                regex: Regex::new(r#"extern\s+"C""#).unwrap(),
                severity: "medium".to_string(),
                message: "FFI boundary detected - requires careful review".to_string(),
                cwe: Some("CWE-242".to_string()),
                fix: Some("Ensure proper null checks and size bounds on FFI boundaries".to_string()),
            },

            // Concurrency
            RustPattern {
                id: "RUST_CONCURRENCY_001".to_string(),
                name: "Static Mut Variable".to_string(),
                regex: Regex::new(r#"static\s+mut\s+"#).unwrap(),
                severity: "high".to_string(),
                message: "Mutable static variable is inherently unsafe".to_string(),
                cwe: Some("CWE-362".to_string()),
                fix: Some("Use Mutex<T>, RwLock<T>, or atomics for thread-safe mutation".to_string()),
            },

            // Input validation
            RustPattern {
                id: "RUST_INPUT_001".to_string(),
                name: "Unchecked Arithmetic".to_string(),
                regex: Regex::new(r#"wrapping_(add|sub|mul)|overflowing_(add|sub|mul)"#).unwrap(),
                severity: "info".to_string(),
                message: "Explicit wrapping arithmetic - verify this is intentional".to_string(),
                cwe: Some("CWE-190".to_string()),
                fix: Some("Document why overflow wrapping is acceptable".to_string()),
            },

            // File operations
            RustPattern {
                id: "RUST_FILE_001".to_string(),
                name: "Path Manipulation".to_string(),
                regex: Regex::new(r#"Path::new|PathBuf::from"#).unwrap(),
                severity: "info".to_string(),
                message: "Path construction - ensure no path traversal vulnerabilities".to_string(),
                cwe: Some("CWE-22".to_string()),
                fix: Some("Validate and canonicalize paths before use".to_string()),
            },

            // Process execution
            RustPattern {
                id: "RUST_EXEC_001".to_string(),
                name: "Command Execution".to_string(),
                regex: Regex::new(r#"std::process::Command|Command::new"#).unwrap(),
                severity: "high".to_string(),
                message: "External command execution - ensure input is sanitized".to_string(),
                cwe: Some("CWE-78".to_string()),
                fix: Some("Validate and escape all command arguments".to_string()),
            },
        ];

        Self { patterns }
    }

    /// Scan Rust file for security issues
    pub fn scan(&self, file: &SourceFile, ast: &AstResult) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for (line_num, line) in file.content.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.regex.is_match(line) {
                    findings.push(Finding {
                        id: pattern.id.clone(),
                        severity: pattern.severity.clone(),
                        message: pattern.message.clone(),
                        path: file.relative_path.to_string_lossy().to_string(),
                        line: line_num + 1,
                        column: 0,
                        snippet: Some(line.trim().to_string()),
                        rule_name: pattern.name.clone(),
                        category: "rust".to_string(),
                        confidence: 0.85,
                        cwe: pattern.cwe.clone(),
                        fix_suggestion: pattern.fix.clone(),
                    });
                }
            }
        }

        // Count unsafe blocks for summary
        let unsafe_count = file.content.matches("unsafe").count();
        if unsafe_count > 5 {
            findings.push(Finding {
                id: "RUST_UNSAFE_DENSITY_001".to_string(),
                severity: "medium".to_string(),
                message: format!("High density of unsafe code: {} occurrences", unsafe_count),
                path: file.relative_path.to_string_lossy().to_string(),
                line: 1,
                column: 0,
                snippet: None,
                rule_name: "High Unsafe Density".to_string(),
                category: "rust".to_string(),
                confidence: 0.7,
                cwe: None,
                fix_suggestion: Some("Consider refactoring to reduce unsafe code usage".to_string()),
            });
        }

        Ok(findings)
    }
}

impl Default for RustScanner {
    fn default() -> Self {
        Self::new()
    }
}
