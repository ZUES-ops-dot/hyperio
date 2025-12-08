//! Configuration management for HyperionScan

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Scan configuration
    pub scan: ScanSettings,
    
    /// Plugin configuration
    pub plugins: PluginSettings,
    
    /// Report configuration
    pub report: ReportSettings,
    
    /// Fuzzing configuration
    pub fuzzing: FuzzSettings,
    
    /// ML detection configuration
    #[serde(default)]
    pub ml: MlSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSettings {
    /// Directories/patterns to exclude from scanning
    pub exclude: Vec<String>,
    
    /// Languages to scan for
    pub languages: Vec<String>,
    
    /// Maximum file size to scan (in bytes)
    pub max_file_size: usize,
    
    /// Follow symbolic links
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSettings {
    /// Directory containing WASM plugins
    pub dir: String,
    
    /// List of enabled plugins (by name, without .wasm extension)
    pub enabled: Vec<String>,
    
    /// Plugin execution timeout in seconds
    pub timeout_seconds: u64,
    
    /// Maximum memory for each plugin (in MB)
    pub max_memory_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSettings {
    /// Output formats (json, markdown, pdf)
    pub formats: Vec<String>,
    
    /// Output directory for reports
    pub output_dir: String,
    
    /// Include source code snippets in reports
    pub include_snippets: bool,
    
    /// Maximum snippet lines
    pub snippet_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzSettings {
    /// Enable fuzzing during scan
    pub enabled: bool,
    
    /// Number of fuzzing iterations
    pub iterations: u32,
    
    /// Fuzzing timeout per target (seconds)
    pub timeout_seconds: u64,
    
    /// Seed for reproducible fuzzing
    pub seed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MlSettings {
    /// Enable ML-based detection
    pub enabled: bool,
    
    /// Path to ONNX model file
    pub model_path: Option<String>,
    
    /// Anomaly threshold (0.0 - 1.0)
    pub threshold: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanSettings {
                exclude: vec![
                    "node_modules".to_string(),
                    "target".to_string(),
                    ".git".to_string(),
                    "build".to_string(),
                    "dist".to_string(),
                    "vendor".to_string(),
                ],
                languages: vec![
                    "solidity".to_string(),
                    "rust".to_string(),
                    "move".to_string(),
                    "vyper".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                ],
                max_file_size: 10 * 1024 * 1024, // 10 MB
                follow_symlinks: false,
            },
            plugins: PluginSettings {
                dir: "./plugins".to_string(),
                enabled: vec![
                    "solidity_scanner".to_string(),
                    "rust_scanner".to_string(),
                    "secret_scanner".to_string(),
                    "pattern_scanner".to_string(),
                ],
                timeout_seconds: 30,
                max_memory_mb: 256,
            },
            report: ReportSettings {
                formats: vec!["json".to_string(), "markdown".to_string()],
                output_dir: "./reports".to_string(),
                include_snippets: true,
                snippet_lines: 5,
            },
            fuzzing: FuzzSettings {
                enabled: false,
                iterations: 1000,
                timeout_seconds: 60,
                seed: None,
            },
            ml: MlSettings {
                enabled: false,
                model_path: None,
                threshold: 0.7,
            },
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        std::fs::write(path, content)?;
        Ok(())
    }
}

// Add toml dependency
fn _toml_dep() {
    // This function exists just to remind us we need toml in Cargo.toml
    // The actual parsing is done above
}
