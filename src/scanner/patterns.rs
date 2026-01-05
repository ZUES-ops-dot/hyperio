//! Pattern-based security scanner

use anyhow::Result;
use regex::Regex;
use crate::core::SourceFile;
use crate::core::AstResult;
use crate::reports::Finding;

/// Pattern-based scanner for generic security issues
pub struct PatternScanner {
    patterns: Vec<SecurityPattern>,
}

struct SecurityPattern {
    id: String,
    name: String,
    regex: Regex,
    severity: String,
    message: String,
    languages: Vec<String>,
}

impl PatternScanner {
    /// Create a new pattern scanner
    pub fn new() -> Self {
        let patterns = vec![
            SecurityPattern {
                id: "GEN_HARDCODED_IP_001".to_string(),
                name: "Hardcoded IP Address".to_string(),
                regex: Regex::new(r#"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#).unwrap(),
                severity: "low".to_string(),
                message: "Hardcoded IP address found".to_string(),
                languages: vec![],
            },
            SecurityPattern {
                id: "GEN_TODO_FIXME_001".to_string(),
                name: "TODO/FIXME Comment".to_string(),
                regex: Regex::new(r#"(?i)(TODO|FIXME|HACK|XXX|BUG)[\s:]+(.+)"#).unwrap(),
                severity: "info".to_string(),
                message: "TODO/FIXME comment found - may indicate incomplete implementation".to_string(),
                languages: vec![],
            },
            SecurityPattern {
                id: "GEN_CONSOLE_LOG_001".to_string(),
                name: "Debug Console Log".to_string(),
                regex: Regex::new(r#"console\.(log|debug|info|warn|error)\s*\("#).unwrap(),
                severity: "low".to_string(),
                message: "Console log statement found - remove before production".to_string(),
                languages: vec!["javascript".to_string(), "typescript".to_string()],
            },
            SecurityPattern {
                id: "GEN_EVAL_001".to_string(),
                name: "Dangerous Eval".to_string(),
                regex: Regex::new(r#"\beval\s*\("#).unwrap(),
                severity: "high".to_string(),
                message: "Use of eval() is dangerous and can lead to code injection".to_string(),
                languages: vec!["javascript".to_string(), "typescript".to_string(), "python".to_string()],
            },
            SecurityPattern {
                id: "GEN_EXEC_001".to_string(),
                name: "Command Execution".to_string(),
                regex: Regex::new(r#"(exec|system|popen|subprocess\.call|os\.system)\s*\("#).unwrap(),
                severity: "high".to_string(),
                message: "Command execution detected - ensure input is properly sanitized".to_string(),
                languages: vec![],
            },
            SecurityPattern {
                id: "GEN_SQL_CONCAT_001".to_string(),
                name: "Potential SQL Injection".to_string(),
                regex: Regex::new(r#"(SELECT|INSERT|UPDATE|DELETE|DROP).*\+.*(\$|var|param|input)"#).unwrap(),
                severity: "critical".to_string(),
                message: "Potential SQL injection - use parameterized queries".to_string(),
                languages: vec![],
            },
            SecurityPattern {
                id: "GEN_WEAK_RANDOM_001".to_string(),
                name: "Weak Random Number".to_string(),
                regex: Regex::new(r#"Math\.random\s*\(\)"#).unwrap(),
                severity: "medium".to_string(),
                message: "Math.random() is not cryptographically secure".to_string(),
                languages: vec!["javascript".to_string(), "typescript".to_string()],
            },
        ];

        Self { patterns }
    }

    /// Scan a file for pattern matches
    pub fn scan(&self, file: &SourceFile, _ast: &AstResult) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let lang_str = format!("{:?}", file.language).to_lowercase();

        for (line_num, line) in file.content.lines().enumerate() {
            for pattern in &self.patterns {
                // Skip if pattern is language-specific and doesn't match
                if !pattern.languages.is_empty() && !pattern.languages.contains(&lang_str) {
                    continue;
                }

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
                        category: "pattern".to_string(),
                        confidence: 0.8,
                        cwe: None,
                        fix_suggestion: None,
                    });
                }
            }
        }

        Ok(findings)
    }
}

impl Default for PatternScanner {
    fn default() -> Self {
        Self::new()
    }
}
