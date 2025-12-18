//! Language detection module

use std::path::Path;
use serde::{Deserialize, Serialize};

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Solidity,
    Rust,
    Move,
    Vyper,
    Cairo,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Unknown,
}

impl Language {
    /// Get language from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "solidity" | "sol" => Language::Solidity,
            "rust" | "rs" => Language::Rust,
            "move" => Language::Move,
            "vyper" | "vy" => Language::Vyper,
            "cairo" => Language::Cairo,
            "javascript" | "js" => Language::JavaScript,
            "typescript" | "ts" => Language::TypeScript,
            "python" | "py" => Language::Python,
            "go" => Language::Go,
            _ => Language::Unknown,
        }
    }

    /// Get file extensions for this language
    pub fn extensions(&self) -> &[&str] {
        match self {
            Language::Solidity => &["sol"],
            Language::Rust => &["rs"],
            Language::Move => &["move"],
            Language::Vyper => &["vy"],
            Language::Cairo => &["cairo"],
            Language::JavaScript => &["js", "mjs", "cjs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Python => &["py"],
            Language::Go => &["go"],
            Language::Unknown => &[],
        }
    }

    /// Get tree-sitter language name
    pub fn tree_sitter_name(&self) -> Option<&str> {
        match self {
            Language::Rust => Some("rust"),
            Language::JavaScript => Some("javascript"),
            Language::TypeScript => Some("typescript"),
            Language::Python => Some("python"),
            Language::Go => Some("go"),
            // These don't have official tree-sitter parsers
            Language::Solidity => None,
            Language::Move => None,
            Language::Vyper => None,
            Language::Cairo => None,
            Language::Unknown => None,
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Solidity => write!(f, "Solidity"),
            Language::Rust => write!(f, "Rust"),
            Language::Move => write!(f, "Move"),
            Language::Vyper => write!(f, "Vyper"),
            Language::Cairo => write!(f, "Cairo"),
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::Python => write!(f, "Python"),
            Language::Go => write!(f, "Go"),
            Language::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Language detector based on file extensions and content
pub struct LanguageDetector {
    enabled_languages: Vec<Language>,
}

impl LanguageDetector {
    /// Create a new detector with enabled languages
    pub fn new(enabled: &[String]) -> Self {
        let enabled_languages: Vec<Language> = enabled
            .iter()
            .map(|s| Language::from_str(s))
            .filter(|l| *l != Language::Unknown)
            .collect();

        Self { enabled_languages }
    }

    /// Detect language from file path
    pub fn detect(&self, path: &Path) -> Option<Language> {
        let extension = path.extension()?.to_str()?;
        
        let language = match extension.to_lowercase().as_str() {
            "sol" => Language::Solidity,
            "rs" => Language::Rust,
            "move" => Language::Move,
            "vy" => Language::Vyper,
            "cairo" => Language::Cairo,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "py" => Language::Python,
            "go" => Language::Go,
            _ => return None,
        };

        // Check if this language is enabled
        if self.enabled_languages.is_empty() || self.enabled_languages.contains(&language) {
            Some(language)
        } else {
            None
        }
    }

    /// Detect language from file content (heuristics)
    pub fn detect_from_content(&self, content: &str) -> Option<Language> {
        // Solidity detection
        if content.contains("pragma solidity") || content.contains("contract ") {
            return Some(Language::Solidity);
        }

        // Vyper detection
        if content.starts_with("# @version") || content.contains("@external") {
            return Some(Language::Vyper);
        }

        // Move detection
        if content.contains("module ") && content.contains("fun ") {
            return Some(Language::Move);
        }

        // Cairo detection  
        if content.contains("from starkware") || content.contains("@external") && content.contains("func ") {
            return Some(Language::Cairo);
        }

        None
    }
}
