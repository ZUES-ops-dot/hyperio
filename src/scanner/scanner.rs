//! Main scanner coordinator

use anyhow::Result;
use std::path::PathBuf;

use crate::config::Config;
use crate::core::{SourceFile, Language, AstResult};
use crate::reports::Finding;
use super::{SolidityScanner, RustScanner, SecretScanner, PatternScanner};

/// Configuration for a scan operation
pub struct ScanConfig {
    /// Target path or URL
    pub target: String,
    
    /// Output directory for reports
    pub output_dir: PathBuf,
    
    /// Report formats to generate
    pub formats: Vec<String>,
    
    /// Enable fuzzing
    pub enable_fuzzing: bool,
    
    /// Fuzzing iterations
    pub fuzz_iterations: u32,
}

/// Main scanner that coordinates all sub-scanners
pub struct Scanner {
    solidity_scanner: SolidityScanner,
    rust_scanner: RustScanner,
    secret_scanner: SecretScanner,
    pattern_scanner: PatternScanner,
}

impl Scanner {
    /// Create a new scanner with config
    pub fn new(config: &Config) -> Self {
        Self {
            solidity_scanner: SolidityScanner::new(),
            rust_scanner: RustScanner::new(),
            secret_scanner: SecretScanner::new(),
            pattern_scanner: PatternScanner::new(),
        }
    }

    /// Scan a single file
    pub fn scan_file(&self, file: &SourceFile, ast: &AstResult) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Run language-specific scanner
        match file.language {
            Language::Solidity => {
                let mut f = self.solidity_scanner.scan(file, ast)?;
                findings.append(&mut f);
            }
            Language::Rust => {
                let mut f = self.rust_scanner.scan(file, ast)?;
                findings.append(&mut f);
            }
            _ => {
                // Run pattern scanner for other languages
                let mut f = self.pattern_scanner.scan(file, ast)?;
                findings.append(&mut f);
            }
        }

        // Always run secret scanner
        let mut secret_findings = self.secret_scanner.scan(file)?;
        findings.append(&mut secret_findings);

        Ok(findings)
    }
}
