//! Plugin ABI definitions
//!
//! Defines the interface between the host and WASM plugins.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Input passed to plugin's analyze function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    /// Programming language of the file
    pub language: String,
    
    /// Relative path to the file
    pub path: String,
    
    /// Source code content
    pub source: String,
    
    /// Serialized AST (JSON)
    pub ast: String,
    
    /// File hash for caching
    pub hash: String,
    
    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Output from plugin's analyze function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    /// List of findings
    pub findings: Vec<PluginFinding>,
    
    /// Plugin-specific metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
    
    /// Any errors during analysis
    #[serde(default)]
    pub errors: Vec<String>,
}

/// A finding reported by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    /// Unique finding ID
    pub id: String,
    
    /// Severity level (critical, high, medium, low, info)
    pub severity: String,
    
    /// Description of the finding
    pub message: String,
    
    /// Line number (1-indexed)
    pub line: usize,
    
    /// Column number (0-indexed)
    #[serde(default)]
    pub column: usize,
    
    /// Rule/check name
    #[serde(default)]
    pub rule_name: Option<String>,
    
    /// CWE identifier
    #[serde(default)]
    pub cwe: Option<String>,
    
    /// Suggested fix
    #[serde(default)]
    pub fix_suggestion: Option<String>,
    
    /// Code snippet showing the issue
    #[serde(default)]
    pub snippet: Option<String>,
    
    /// Confidence score (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    0.8
}

/// Information about a loaded plugin
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name
    pub name: String,
    
    /// Plugin version
    pub version: String,
    
    /// Path to the .wasm file
    pub path: PathBuf,
    
    /// Whether the plugin is enabled
    pub enabled: bool,
}

/// Plugin manifest (optional, for advanced plugins)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name
    pub name: String,
    
    /// Plugin version
    pub version: String,
    
    /// Author
    pub author: Option<String>,
    
    /// Description
    pub description: Option<String>,
    
    /// Supported languages
    pub languages: Vec<String>,
    
    /// Required host capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl Default for PluginOutput {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            metadata: std::collections::HashMap::new(),
            errors: Vec::new(),
        }
    }
}
