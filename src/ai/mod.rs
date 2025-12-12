//! HyperionScan AI Integration Module
//! 
//! Bridges the Rust core engine with Python ML agents for intelligent vulnerability hunting.
//! This creates a hybrid system: fast Rust scanning + deep AI analysis + zero false-positive validation.

use anyhow::{Result, Context};
use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

/// AI Analysis Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIConfig {
    /// Enable ML agents (requires Ollama)
    pub enable_ml_agents: bool,
    
    /// Enable exploit validation (requires Foundry)
    pub enable_exploit_validation: bool,
    
    /// Ollama server URL
    pub ollama_url: String,
    
    /// Suspicion threshold for LLM analysis
    pub suspicion_threshold: f64,
    
    /// Maximum regions to send to LLM
    pub max_llm_regions: usize,
    
    /// Python interpreter path
    pub python_path: PathBuf,
}

impl Default for AIConfig {
    fn default() -> Self {
        Self {
            enable_ml_agents: true,
            enable_exploit_validation: true,
            ollama_url: "http://localhost:11434".to_string(),
            suspicion_threshold: 0.5,
            max_llm_regions: 50,
            python_path: PathBuf::from("python"),
        }
    }
}

/// AI Analysis Results
#[derive(Debug, Serialize, Deserialize)]
pub struct AIResults {
    /// Target analyzed
    pub target: String,
    
    /// Analysis timestamp
    pub timestamp: u64,
    
    /// Hunter agent results (fast pattern triage)
    pub hunter_results: HunterResults,
    
    /// LLM agent results (deep semantic analysis)
    pub llm_results: Option<LLMResults>,
    
    /// Exploit validation results (zero false positives)
    pub exploit_results: Option<ExploitResults>,
    
    /// Final consolidated findings
    pub final_findings: Vec<AIFinding>,
    
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// Hunter Agent Results (Fast Pattern Triage)
#[derive(Debug, Serialize, Deserialize)]
pub struct HunterResults {
    /// Total code regions scanned
    pub total_regions: usize,
    
    /// High-suspicion regions selected for LLM
    pub high_suspicion_regions: usize,
    
    /// Processing time in seconds
    pub processing_time_seconds: f64,
    
    /// Efficiency (percentage filtered out)
    pub efficiency_percentage: f64,
}

/// LLM Agent Results (Deep Semantic Analysis)
#[derive(Debug, Serialize, Deserialize)]
pub struct LLMResults {
    /// Individual agent results
    pub agent_results: std::collections::HashMap<String, AgentResult>,
    
    /// Total processing time
    pub processing_time_seconds: f64,
    
    /// Average confidence across all agents
    pub average_confidence: f64,
}

/// Individual LLM Agent Result
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentResult {
    /// Agent name (hunter, taint, cross, exploit, synth)
    pub agent_name: String,
    
    /// Model used for analysis
    pub model_used: String,
    
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    
    /// Processing time
    pub processing_time_seconds: f64,
    
    /// Raw response from LLM
    pub response: String,
}

/// Exploit Validation Results (Zero False Positives)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExploitResults {
    /// Total exploits tested
    pub exploits_tested: usize,
    
    /// Successfully executed exploits
    pub successful_exploits: usize,
    
    /// False positives eliminated
    pub false_positives_eliminated: usize,
    
    /// Processing time
    pub processing_time_seconds: f64,
    
    /// Accuracy percentage
    pub accuracy_percentage: f64,
}

/// AI-Generated Finding with Validation
#[derive(Debug, Serialize, Deserialize)]
pub struct AIFinding {
    /// Unique finding ID
    pub id: String,
    
    /// File path
    pub file_path: String,
    
    /// Line number
    pub line_number: usize,
    
    /// Vulnerability type
    pub vulnerability_type: String,
    
    /// Severity (validated by exploit)
    pub severity: String,
    
    /// Description
    pub description: String,
    
    /// AI confidence score
    pub confidence: f64,
    
    /// Exploit validation status
    pub exploit_validated: bool,
    
    /// Generated exploit code (if available)
    pub exploit_code: Option<String>,
    
    /// Remediation suggestions
    pub remediation: Vec<String>,
}

/// Performance Metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total analysis time
    pub total_time_seconds: f64,
    
    /// Time per stage
    pub stage_times: std::collections::HashMap<String, f64>,
    
    /// Memory usage (MB)
    pub memory_usage_mb: f64,
    
    /// CPU utilization percentage
    pub cpu_utilization: f64,
}

/// AI Engine - Coordinates intelligent vulnerability hunting
pub struct AIEngine {
    config: AIConfig,
    python_path: PathBuf,
}

impl AIEngine {
    /// Create new AI engine with configuration
    pub fn new(config: AIConfig) -> Self {
        let python_path = config.python_path.clone();
        Self { config, python_path }
    }
    
    /// Run complete AI analysis on target directory
    pub async fn analyze(&self, target_path: &Path) -> Result<AIResults> {
        info!("AI Starting HyperionAI analysis of: {:?}", target_path);
        
        // Check if Python AI system is available
        self.check_dependencies().await?;
        
        // Run the Python AI orchestrator
        let results = self.run_ai_analysis(target_path).await?;
        
        info!("Success AI analysis complete. {} findings validated.", results.final_findings.len());
        
        Ok(results)
    }
    
    /// Check if required dependencies are available
    async fn check_dependencies(&self) -> Result<()> {
        let mut issues = Vec::new();
        
        // Check Python availability
        let python_check = Command::new(&self.python_path)
            .arg("--version")
            .output();
            
        match python_check {
            Ok(output) if output.status.success() => {
                info!("Success Python available");
            }
            Ok(_) => {
                warn!("Warning Python not available. AI features disabled.");
                issues.push("Python not found");
            }
            Err(e) => {
                warn!("Warning Error checking Python: {}", e);
                issues.push("Python check failed");
            }
        }
        
        // Check if AI scripts exist - use multiple possible paths
        let possible_paths = vec![
            // Development path (cargo run)
            Path::new(env!("CARGO_MANIFEST_DIR")).join("ml_agents").join("hyperion_ai.py"),
            // Installed binary path
            self.python_path.parent().unwrap_or_else(|| Path::new(".")).join("ml_agents").join("hyperion_ai.py"),
            // Current directory
            Path::new("./ml_agents/hyperion_ai.py"),
        ];
        
        let mut ai_script_found = false;
        for path in &possible_paths {
            if path.exists() {
                info!("Success AI scripts found at: {:?}", path);
                ai_script_found = true;
                break;
            }
        }
        
        if !ai_script_found {
            warn!("Warning AI scripts not found in any location");
            issues.push("AI scripts not found");
        }
        
        // Return warning instead of error for graceful fallback
        if !issues.is_empty() {
            warn!("Warning AI dependencies missing: {}. Falling back to pattern-based scanning.", issues.join(", "));
            return Err(anyhow::anyhow!("AI dependencies unavailable - will use pattern-based scanning"));
        }
        
        info!("Success AI dependencies verified");
        Ok(())
    }
    
    /// Execute the Python AI orchestrator
    async fn run_ai_analysis(&self, target_path: &Path) -> Result<AIResults> {
        // Find the AI script using the same path resolution as check_dependencies
        let possible_paths = vec![
            // Development path (cargo run)
            Path::new(env!("CARGO_MANIFEST_DIR")).join("ml_agents").join("hyperion_ai.py"),
            // Installed binary path
            self.python_path.parent().unwrap_or_else(|| Path::new(".")).join("ml_agents").join("hyperion_ai.py"),
            // Current directory
            Path::new("./ml_agents/hyperion_ai.py"),
        ];
        
        let ai_script = possible_paths.into_iter()
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("AI script not found"))?;
            
        // Create temporary output file
        let temp_output = std::env::temp_dir().join("hyperion_ai_results.json");
        
        // Build command
        let mut cmd = Command::new(&self.python_path);
        cmd.arg(&ai_script)
           .arg(target_path)
           .arg(&temp_output);
           
        // Set environment variables for configuration
        cmd.env("HYPERION_AI_ENABLE_ML", if self.config.enable_ml_agents { "1" } else { "0" });
        cmd.env("HYPERION_AI_ENABLE_EXPLOITS", if self.config.enable_exploit_validation { "1" } else { "0" });
        cmd.env("HYPERION_AI_OLLAMA_URL", &self.config.ollama_url);
        cmd.env("HYPERION_AI_THRESHOLD", &self.config.suspicion_threshold.to_string());
        
        info!("AI Executing AI analysis...");
        
        // Run the command
        let output = cmd.output()
            .with_context(|| "Failed to execute AI analysis script")?;
            
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            error!("AI analysis failed: {}", stderr);
            error!("stdout: {}", stdout);
            return Err(anyhow::anyhow!("AI analysis script failed"));
        }
        
        // Read results
        let results_json = std::fs::read_to_string(&temp_output)
            .with_context(|| "Failed to read AI results")?;
            
        let results: AIResults = serde_json::from_str(&results_json)
            .with_context(|| "Failed to parse AI results")?;
            
        // Clean up temp file
        let _ = std::fs::remove_file(&temp_output);
        
        Ok(results)
    }
    
    /// Convert AI findings to standard Hyperion findings
    pub fn convert_findings(&self, ai_results: &AIResults) -> Vec<crate::reports::Finding> {
        let mut findings = Vec::new();
        
        for ai_finding in &ai_results.final_findings {
            let finding = crate::reports::Finding {
                id: ai_finding.id.clone(),
                severity: ai_finding.severity.clone(),
                message: ai_finding.description.clone(),
                path: ai_finding.file_path.clone(),
                line: ai_finding.line_number,
                column: 0,
                snippet: None,
                rule_name: format!("AI-{}", ai_finding.vulnerability_type),
                category: "ai-validated".to_string(),
                confidence: ai_finding.confidence,
                cwe: self.guess_cwe(&ai_finding.vulnerability_type),
                fix_suggestion: Some(ai_finding.remediation.join("; ")),
            };
            
            findings.push(finding);
        }
        
        findings
    }
    
    /// Guess CWE ID based on vulnerability type
    fn guess_cwe(&self, vuln_type: &str) -> Option<String> {
        match vuln_type.to_lowercase().as_str() {
            "reentrancy" => Some("CWE-841".to_string()),
            "access_control" => Some("CWE-284".to_string()),
            "delegatecall" => Some("CWE-843".to_string()),
            "integer_overflow" => Some("CWE-190".to_string()),
            "flashloan" => Some("CWE-841".to_string()),
            _ => Some("CWE-000".to_string()),
        }
    }
}

impl Default for AIEngine {
    fn default() -> Self {
        Self::new(AIConfig::default())
    }
}

/// Public interface for AI integration
pub mod interface {
    use super::*;
    
    /// Quick AI analysis function for integration with main engine
    pub async fn quick_ai_scan(target_path: &Path) -> Result<Vec<crate::reports::Finding>> {
        let config = AIConfig::default();
        let engine = AIEngine::new(config);
        
        let results = engine.analyze(target_path).await?;
        Ok(engine.convert_findings(&results))
    }
    
    /// Full AI analysis with detailed results
    pub async fn full_ai_analysis(target_path: &Path, config: AIConfig) -> Result<AIResults> {
        let engine = AIEngine::new(config);
        engine.analyze(target_path).await
    }
}
