//! Fuzzing module for mutation-based testing

use anyhow::Result;
use crate::core::SourceFile;
use crate::reports::Finding;
use tracing::{debug, info};
use std::collections::HashMap;

/// Mutation-based fuzzer
pub struct Fuzzer {
    /// Fuzzing seed for reproducibility
    seed: u64,
    /// Maximum iterations
    max_iterations: u32,
    /// Mutation strategies
    strategies: Vec<MutationStrategy>,
}

#[derive(Clone)]
enum MutationStrategy {
    /// Flip random bits
    BitFlip,
    /// Replace numbers with edge cases
    NumberEdgeCases,
    /// Remove characters
    Deletion,
    /// Duplicate sections
    Duplication,
    /// Insert special characters
    SpecialChars,
    /// Swap adjacent tokens
    TokenSwap,
}

/// Result of a fuzz run
pub struct FuzzResult {
    pub findings: Vec<Finding>,
    pub iterations: u32,
    pub crashes: u32,
    pub coverage: f64,
}

impl Fuzzer {
    /// Create a new fuzzer
    pub fn new(seed: Option<u64>, max_iterations: u32) -> Self {
        Self {
            seed: seed.unwrap_or_else(|| {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }),
            max_iterations,
            strategies: vec![
                MutationStrategy::BitFlip,
                MutationStrategy::NumberEdgeCases,
                MutationStrategy::Deletion,
                MutationStrategy::Duplication,
                MutationStrategy::SpecialChars,
                MutationStrategy::TokenSwap,
            ],
        }
    }

    /// Fuzz a source file
    pub fn fuzz(&self, file: &SourceFile) -> Result<FuzzResult> {
        let mut findings = Vec::new();
        let mut crashes = 0;

        info!("Fuzzing: {:?}", file.relative_path);
        debug!("Using seed: {}", self.seed);

        // Extract fuzzable targets from the source
        let targets = self.extract_targets(file);
        debug!("Found {} fuzzable targets", targets.len());

        for (iteration, target) in targets.iter().cycle().take(self.max_iterations as usize).enumerate() {
            // Generate mutated input
            let mutated = self.mutate(target, iteration as u64);
            
            // Check for interesting patterns in mutated output
            if let Some(finding) = self.check_mutation_result(&mutated, file, iteration) {
                findings.push(finding);
            }
        }

        Ok(FuzzResult {
            findings,
            iterations: self.max_iterations,
            crashes,
            coverage: 0.0, // TODO: Implement coverage tracking
        })
    }

    /// Extract fuzzable targets from source
    fn extract_targets(&self, file: &SourceFile) -> Vec<String> {
        let mut targets = Vec::new();
        
        // Extract function calls
        let fn_regex = regex::Regex::new(r#"\w+\s*\([^)]*\)"#).unwrap();
        for cap in fn_regex.find_iter(&file.content) {
            targets.push(cap.as_str().to_string());
        }

        // Extract numeric literals
        let num_regex = regex::Regex::new(r#"\b\d+\b"#).unwrap();
        for cap in num_regex.find_iter(&file.content) {
            targets.push(cap.as_str().to_string());
        }

        // Extract string literals
        let str_regex = regex::Regex::new(r#"["'][^"']*["']"#).unwrap();
        for cap in str_regex.find_iter(&file.content) {
            targets.push(cap.as_str().to_string());
        }

        targets
    }

    /// Apply mutation to target
    fn mutate(&self, target: &str, iteration: u64) -> String {
        let strategy_idx = (self.seed.wrapping_add(iteration) % self.strategies.len() as u64) as usize;
        let strategy = &self.strategies[strategy_idx];

        match strategy {
            MutationStrategy::BitFlip => self.bit_flip(target, iteration),
            MutationStrategy::NumberEdgeCases => self.number_edge_cases(target),
            MutationStrategy::Deletion => self.deletion(target, iteration),
            MutationStrategy::Duplication => self.duplication(target),
            MutationStrategy::SpecialChars => self.special_chars(target, iteration),
            MutationStrategy::TokenSwap => self.token_swap(target),
        }
    }

    fn bit_flip(&self, target: &str, iteration: u64) -> String {
        let mut bytes = target.as_bytes().to_vec();
        if !bytes.is_empty() {
            let idx = (iteration as usize) % bytes.len();
            bytes[idx] ^= 0xFF;
        }
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn number_edge_cases(&self, target: &str) -> String {
        let edge_cases = ["0", "-1", "2147483647", "2147483648", "18446744073709551615", ""];
        if let Ok(num) = target.parse::<i64>() {
            let idx = (num.abs() as usize) % edge_cases.len();
            edge_cases[idx].to_string()
        } else {
            target.to_string()
        }
    }

    fn deletion(&self, target: &str, iteration: u64) -> String {
        let chars: Vec<char> = target.chars().collect();
        if chars.len() > 1 {
            let idx = (iteration as usize) % chars.len();
            chars.iter()
                .enumerate()
                .filter(|(i, _)| *i != idx)
                .map(|(_, c)| *c)
                .collect()
        } else {
            String::new()
        }
    }

    fn duplication(&self, target: &str) -> String {
        format!("{}{}", target, target)
    }

    fn special_chars(&self, target: &str, iteration: u64) -> String {
        let specials = ["\0", "\n", "\r", "\\", "'", "\"", ";", "--", "/*", "*/"];
        let idx = (iteration as usize) % specials.len();
        format!("{}{}", target, specials[idx])
    }

    fn token_swap(&self, target: &str) -> String {
        let tokens: Vec<&str> = target.split_whitespace().collect();
        if tokens.len() >= 2 {
            let mut swapped = tokens.clone();
            swapped.swap(0, tokens.len() - 1);
            swapped.join(" ")
        } else {
            target.to_string()
        }
    }

    /// Check if mutation produced interesting result
    fn check_mutation_result(&self, mutated: &str, file: &SourceFile, iteration: usize) -> Option<Finding> {
        // Check for patterns that might indicate issues
        
        // Integer overflow patterns
        if mutated.contains("18446744073709551615") || mutated.contains("2147483647") {
            return Some(Finding {
                id: "FUZZ_OVERFLOW_001".to_string(),
                severity: "medium".to_string(),
                message: "Potential integer overflow with edge case value".to_string(),
                path: file.relative_path.to_string_lossy().to_string(),
                line: 1,
                column: 0,
                snippet: Some(mutated.chars().take(100).collect()),
                rule_name: "Fuzzer: Integer Edge Case".to_string(),
                category: "fuzzing".to_string(),
                confidence: 0.5,
                cwe: Some("CWE-190".to_string()),
                fix_suggestion: Some("Add bounds checking for numeric inputs".to_string()),
            });
        }

        // SQL injection patterns
        if mutated.contains("--") || mutated.contains("/*") {
            return Some(Finding {
                id: "FUZZ_INJECTION_001".to_string(),
                severity: "low".to_string(),
                message: "Fuzzer injected SQL comment - review input handling".to_string(),
                path: file.relative_path.to_string_lossy().to_string(),
                line: 1,
                column: 0,
                snippet: Some(mutated.chars().take(100).collect()),
                rule_name: "Fuzzer: Injection Pattern".to_string(),
                category: "fuzzing".to_string(),
                confidence: 0.3,
                cwe: Some("CWE-89".to_string()),
                fix_suggestion: Some("Ensure proper input sanitization".to_string()),
            });
        }

        None
    }
}

/// Fuzz multiple files
pub fn fuzz_files(files: &[SourceFile], iterations: u32, seed: Option<u64>) -> Result<Vec<Finding>> {
    let fuzzer = Fuzzer::new(seed, iterations);
    let mut all_findings = Vec::new();

    for file in files {
        let result = fuzzer.fuzz(file)?;
        all_findings.extend(result.findings);
    }

    Ok(all_findings)
}
