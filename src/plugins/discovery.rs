//! Plugin discovery module
//!
//! Discovers and loads plugins from the plugins directory by reading plugin.toml manifests.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, debug, warn};

/// Plugin manifest loaded from plugin.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    
    /// Plugin type: "builtin", "cli", or "wasm"
    #[serde(rename = "type")]
    pub plugin_type: String,
    
    /// For CLI plugins: command to execute
    #[serde(default)]
    pub command: Option<String>,
    
    /// For CLI plugins: arguments
    #[serde(default)]
    pub args: Vec<String>,
    
    /// For WASM plugins: path to .wasm file
    #[serde(default)]
    pub wasm_file: Option<String>,
    
    /// Supported languages (empty = all)
    #[serde(default)]
    pub languages: Vec<String>,
    
    /// Whether plugin is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Discovered plugin with its location
#[derive(Debug, Clone)]
pub struct DiscoveredPlugin {
    pub manifest: PluginManifest,
    pub directory: PathBuf,
}

impl DiscoveredPlugin {
    pub fn name(&self) -> &str {
        &self.manifest.plugin.name
    }
    
    pub fn plugin_type(&self) -> &str {
        &self.manifest.plugin.plugin_type
    }
    
    pub fn is_enabled(&self) -> bool {
        self.manifest.plugin.enabled
    }
    
    pub fn supports_language(&self, lang: &str) -> bool {
        let langs = &self.manifest.plugin.languages;
        langs.is_empty() || langs.iter().any(|l| l.eq_ignore_ascii_case(lang))
    }
}

/// Discover all plugins in the plugins directory
pub fn discover_plugins(plugins_dir: &Path) -> Result<Vec<DiscoveredPlugin>> {
    let mut plugins = Vec::new();
    
    if !plugins_dir.exists() {
        warn!("Plugins directory does not exist: {:?}", plugins_dir);
        return Ok(plugins);
    }
    
    info!("Inspect Discovering plugins in {:?}", plugins_dir);
    
    for entry in std::fs::read_dir(plugins_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if !path.is_dir() {
            continue;
        }
        
        let manifest_path = path.join("plugin.toml");
        
        if manifest_path.exists() {
            match load_manifest(&manifest_path) {
                Ok(manifest) => {
                    debug!("  Found plugin: {} ({})", manifest.plugin.name, manifest.plugin.plugin_type);
                    plugins.push(DiscoveredPlugin {
                        manifest,
                        directory: path,
                    });
                }
                Err(e) => {
                    warn!("  Failed to load {:?}: {}", manifest_path, e);
                }
            }
        }
    }
    
    info!("  Discovered {} plugins", plugins.len());
    Ok(plugins)
}

/// Load a plugin manifest from plugin.toml
fn load_manifest(path: &Path) -> Result<PluginManifest> {
    let content = std::fs::read_to_string(path)
        .context("Failed to read plugin.toml")?;
    
    let manifest: PluginManifest = toml::from_str(&content)
        .context("Failed to parse plugin.toml")?;
    
    Ok(manifest)
}

/// Filter plugins by enabled status and config
pub fn filter_enabled_plugins(
    plugins: Vec<DiscoveredPlugin>,
    enabled_list: &[String],
) -> Vec<DiscoveredPlugin> {
    plugins
        .into_iter()
        .filter(|p| {
            // Check if plugin itself is enabled
            if !p.is_enabled() {
                return false;
            }
            
            // If enabled_list is empty, enable all
            if enabled_list.is_empty() {
                return true;
            }
            
            // Check if plugin is in enabled list
            enabled_list.iter().any(|name| name == p.name())
        })
        .collect()
}
