//! Plugin Manager - coordinates loading and execution of all plugin types
//!
//! Supports:
//! - CLI plugins (spawned processes with JSON stdin/stdout)
//! - WASM plugins (sandboxed WebAssembly modules)
//! - Builtin plugins (compiled into the engine)

use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::{info, warn, debug};

use crate::config::PluginSettings;
use crate::core::SourceFile;
use crate::core::AstResult;
use crate::reports::Finding;
use super::discovery::{discover_plugins, filter_enabled_plugins, DiscoveredPlugin};
use super::cli_runner::CliPluginRunner;
use super::abi::PluginInput;

/// Manages all plugin types
pub struct PluginManager {
    /// Discovered and enabled plugins
    plugins: Vec<DiscoveredPlugin>,
    
    /// CLI plugin runner
    cli_runner: CliPluginRunner,
    
    /// Plugins directory
    plugins_dir: PathBuf,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(plugin_dir: &Path, settings: &PluginSettings) -> Result<Self> {
        info!("Package Initializing plugin manager...");
        
        // Discover all plugins
        let all_plugins = discover_plugins(plugin_dir)?;
        
        // Filter to enabled plugins
        let plugins = filter_enabled_plugins(all_plugins, &settings.enabled);
        
        info!("  {} plugins enabled", plugins.len());
        for p in &plugins {
            info!("    Success {} ({}) - {}", p.name(), p.plugin_type(), 
                  p.manifest.plugin.description);
        }
        
        let cli_runner = CliPluginRunner::new(settings.timeout_seconds);
        
        Ok(Self {
            plugins,
            cli_runner,
            plugins_dir: plugin_dir.to_path_buf(),
        })
    }

    /// Analyze a file using all enabled plugins
    pub fn analyze(&self, file: &SourceFile, ast: &AstResult) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();
        
        let language = format!("{:?}", file.language).to_lowercase();
        
        // Build plugin input
        let input = PluginInput {
            language: language.clone(),
            path: file.relative_path.to_string_lossy().to_string(),
            source: file.content.clone(),
            ast: ast.ast_json.clone(),
            hash: file.hash.clone(),
            metadata: std::collections::HashMap::new(),
        };

        for plugin in &self.plugins {
            // Skip plugins that don't support this language
            if !plugin.supports_language(&language) {
                continue;
            }
            
            // Skip builtin plugins (handled separately by scanner)
            if plugin.plugin_type() == "builtin" {
                continue;
            }
            
            debug!("Running plugin: {} ({})", plugin.name(), plugin.plugin_type());
            
            let findings = match plugin.plugin_type() {
                "cli" => {
                    match self.cli_runner.run(plugin, &input) {
                        Ok(f) => f,
                        Err(e) => {
                            warn!("CLI plugin {} failed: {}", plugin.name(), e);
                            vec![]
                        }
                    }
                }
                "wasm" => {
                    // WASM plugins - TODO: implement wasmtime loading
                    debug!("WASM plugin {} skipped (not yet implemented)", plugin.name());
                    vec![]
                }
                _ => {
                    warn!("Unknown plugin type: {}", plugin.plugin_type());
                    vec![]
                }
            };
            
            all_findings.extend(findings);
        }

        Ok(all_findings)
    }

    /// Get list of all discovered plugins
    pub fn list_plugins(&self) -> Vec<PluginSummary> {
        self.plugins
            .iter()
            .map(|p| PluginSummary {
                name: p.name().to_string(),
                version: p.manifest.plugin.version.clone(),
                plugin_type: p.plugin_type().to_string(),
                description: p.manifest.plugin.description.clone(),
                enabled: p.is_enabled(),
                languages: p.manifest.plugin.languages.clone(),
            })
            .collect()
    }
    
    /// Check if any CLI plugins are available
    pub fn has_cli_plugins(&self) -> bool {
        self.plugins.iter().any(|p| p.plugin_type() == "cli")
    }
}

/// Summary of a plugin for display
#[derive(Debug, Clone)]
pub struct PluginSummary {
    pub name: String,
    pub version: String,
    pub plugin_type: String,
    pub description: String,
    pub enabled: bool,
    pub languages: Vec<String>,
}
