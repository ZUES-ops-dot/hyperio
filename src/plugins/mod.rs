//! Plugin system
//!
//! This module provides the infrastructure for loading and executing plugins:
//! - CLI plugins (spawn process, JSON in/out)
//! - WASM plugins (sandboxed WebAssembly)
//! - Builtin scanners (Rust code)

mod loader;
mod manager;
mod abi;
mod discovery;
mod cli_runner;

pub use loader::PluginLoader;
pub use manager::PluginManager;
pub use abi::{PluginInput, PluginOutput, PluginInfo};
pub use discovery::{discover_plugins, DiscoveredPlugin, PluginManifest, filter_enabled_plugins};
pub use cli_runner::CliPluginRunner;

use anyhow::Result;
use std::path::Path;

/// List installed plugins in a directory (reads plugin.toml manifests)
pub fn list_plugins(dir: &Path) -> Result<Vec<PluginInfo>> {
    let discovered = discover_plugins(dir)?;
    
    let plugins = discovered
        .into_iter()
        .map(|p| PluginInfo {
            name: p.manifest.plugin.name,
            version: p.manifest.plugin.version,
            path: p.directory,
            enabled: p.manifest.plugin.enabled,
        })
        .collect();
    
    Ok(plugins)
}
