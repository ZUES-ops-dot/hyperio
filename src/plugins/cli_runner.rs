//! CLI Plugin Runner
//!
//! Executes CLI-based plugins by spawning a process and communicating via JSON stdin/stdout.

use anyhow::{Result, Context};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::{debug, warn};

use super::discovery::DiscoveredPlugin;
use super::abi::{PluginInput, PluginOutput};
use crate::reports::Finding;

/// Runner for CLI-based plugins
pub struct CliPluginRunner {
    timeout: Duration,
}

impl CliPluginRunner {
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_seconds),
        }
    }

    /// Run a CLI plugin with the given input
    pub fn run(&self, plugin: &DiscoveredPlugin, input: &PluginInput) -> Result<Vec<Finding>> {
        let config = &plugin.manifest.plugin;
        
        let command = config.command.as_ref()
            .context("CLI plugin missing 'command' in manifest")?;
        
        debug!("Running CLI plugin: {} ({})", plugin.name(), command);
        
        // Build the command
        let mut cmd = Command::new(command);
        cmd.current_dir(&plugin.directory);
        cmd.args(&config.args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        
        // Spawn the process
        let mut child = cmd.spawn()
            .context(format!("Failed to spawn plugin: {}", plugin.name()))?;
        
        // Write input JSON to stdin
        let input_json = serde_json::to_string(input)?;
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(input_json.as_bytes())?;
        }
        
        // Wait for completion with timeout
        let output = child.wait_with_output()
            .context("Plugin execution failed")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Plugin {} exited with error: {}", plugin.name(), stderr);
        }
        
        // Parse output JSON
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        if stdout.trim().is_empty() {
            return Ok(vec![]);
        }
        
        let plugin_output: PluginOutput = serde_json::from_str(&stdout)
            .context(format!("Failed to parse plugin output: {}", stdout.chars().take(100).collect::<String>()))?;
        
        // Log any errors from plugin
        for error in &plugin_output.errors {
            warn!("Plugin {} error: {}", plugin.name(), error);
        }
        
        // Convert plugin findings to our Finding type
        let findings: Vec<Finding> = plugin_output.findings
            .into_iter()
            .map(|f| Finding {
                id: f.id,
                severity: f.severity,
                message: f.message,
                path: input.path.clone(),
                line: f.line,
                column: f.column,
                snippet: f.snippet,
                rule_name: f.rule_name.unwrap_or_else(|| plugin.name().to_string()),
                category: format!("plugin:{}", plugin.name()),
                confidence: f.confidence,
                cwe: f.cwe,
                fix_suggestion: f.fix_suggestion,
            })
            .collect();
        
        Ok(findings)
    }
}
