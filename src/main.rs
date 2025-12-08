//! HyperionScan - Local-Only Security Scanner
//!
//! Main entry point for the CLI application.

mod config;
mod core;
mod plugins;
mod reports;
mod scanner;
mod ai;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::Config;
use crate::core::Engine;
use crate::ai::{AIEngine, AIConfig};

#[derive(Parser)]
#[command(name = "hyperion")]
#[command(author = "HyperionScan Team")]
#[command(version = "0.1.0")]
#[command(about = "Local-only smart contract and code security scanner", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or Git repository for vulnerabilities
    Scan {
        /// Path to directory or Git URL to scan
        target: String,

        /// Output directory for reports
        #[arg(short, long, default_value = "./reports")]
        output: PathBuf,

        /// Report formats (json, markdown, pdf)
        #[arg(short, long, default_values = ["json", "markdown"])]
        format: Vec<String>,

        /// Enable fuzzing during scan
        #[arg(long)]
        fuzz: bool,

        /// Number of fuzzing iterations
        #[arg(long, default_value = "100")]
        fuzz_iterations: u32,

        /// Enable AI-powered analysis (LLM agents)
        #[arg(long)]
        ai: bool,

        /// Enable exploit validation for zero false positives
        #[arg(long)]
        validate: bool,
    },

    /// AI-powered vulnerability hunting with multi-agent analysis
    AI {
        /// Path to directory or Git URL to analyze
        target: String,

        /// Output file for AI report
        #[arg(short, long, default_value = "./ai_report.json")]
        output: PathBuf,

        /// Enable exploit validation
        #[arg(long)]
        validate: bool,

        /// Suspicion threshold for LLM analysis (0.0-1.0)
        #[arg(long, default_value = "0.5")]
        threshold: f64,

        /// Maximum regions to analyze with LLM
        #[arg(long, default_value = "50")]
        max_regions: usize,
    },

    /// List installed WASM plugins
    Plugins {
        /// Plugin directory
        #[arg(short, long, default_value = "./plugins")]
        dir: PathBuf,
    },

    /// View the last scan report
    Report {
        /// Report directory
        #[arg(short, long, default_value = "./reports")]
        dir: PathBuf,

        /// Report format to view
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Export last scan as PDF
    Pdf {
        /// Report directory
        #[arg(short, long, default_value = "./reports")]
        dir: PathBuf,

        /// Output PDF path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show scan findings summary
    Findings {
        /// Report directory
        #[arg(short, long, default_value = "./reports")]
        dir: PathBuf,

        /// Filter by severity (critical, high, medium, low, info)
        #[arg(short, long)]
        severity: Option<String>,
    },

    /// Initialize a new configuration file
    Init {
        /// Output path for config file
        #[arg(short, long, default_value = "./hyperion.toml")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let config = if let Some(config_path) = &cli.config {
        Config::load(config_path)?
    } else {
        // Try to load from default locations
        let default_paths = ["./hyperion.toml", "hyperion.toml"];
        let mut loaded_config = None;
        
        for path in default_paths {
            let p = std::path::Path::new(path);
            if p.exists() {
                match Config::load(p) {
                    Ok(cfg) => {
                        info!("Checklist Loaded config from: {}", path);
                        loaded_config = Some(cfg);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load {}: {}", path, e);
                    }
                }
            }
        }
        
        loaded_config.unwrap_or_default()
    };

    // Execute command
    match cli.command {
        Commands::Scan {
            target,
            output,
            format,
            fuzz,
            fuzz_iterations,
            ai,
            validate,
        } => {
            if ai || validate {
                info!("AI Starting AI-Enhanced HyperionScan...");
                info!("Target: {}", target);
                info!("AI Analysis: {}", ai);
                info!("Exploit Validation: {}", validate);

                // Configure AI engine
                let ai_config = AIConfig {
                    enable_ml_agents: ai,
                    enable_exploit_validation: validate,
                    ollama_url: "http://localhost:11434".to_string(),
                    suspicion_threshold: 0.5,
                    max_llm_regions: 50,
                    python_path: std::path::PathBuf::from("python"),
                };

                let ai_engine = AIEngine::new(ai_config);
                let target_path = std::path::Path::new(&target);
                
                // Run AI analysis
                let ai_results = ai_engine.analyze(target_path).await?;
                
                // Convert AI findings to standard format
                let ai_findings = ai_engine.convert_findings(&ai_results);
                
                // Also run standard scan for comparison
                let mut engine = Engine::new(config)?;
                let scan_config = scanner::ScanConfig {
                    target: target.clone(),
                    output_dir: output.clone(),
                    formats: format.clone(),
                    enable_fuzzing: fuzz,
                    fuzz_iterations,
                };

                let standard_results = engine.scan(scan_config).await?;
                
                // Merge results (AI findings take precedence)
                let mut all_findings = standard_results.findings;
                all_findings.extend(ai_findings);
                
                info!("Success AI-Enhanced Scan complete!");
                info!("   Standard findings: {}", standard_results.findings.len());
                info!("   AI-validated findings: {}", ai_results.final_findings.len());
                info!("   Total findings: {}", all_findings.len());
                
                // Count severities
                let critical = all_findings.iter().filter(|f| f.severity == "critical").count();
                let high = all_findings.iter().filter(|f| f.severity == "high").count();
                let medium = all_findings.iter().filter(|f| f.severity == "medium").count();
                let low = all_findings.iter().filter(|f| f.severity == "low").count();
                
                info!("   Critical: {} (AI-validated)", critical);
                info!("   High: {}", high);
                info!("   Medium: {}", medium);
                info!("   Low: {}", low);
                
                // Save AI results
                let ai_report_path = output.join("ai_analysis.json");
                let ai_json = serde_json::to_string_pretty(&ai_results)?;
                std::fs::write(ai_report_path, ai_json)?;
                
            } else {
                info!("Inspect Starting HyperionScan...");
                info!("Target: {}", target);

                let mut engine = Engine::new(config)?;
                
                let scan_config = scanner::ScanConfig {
                    target,
                    output_dir: output,
                    formats: format,
                    enable_fuzzing: fuzz,
                    fuzz_iterations,
                };

                let results = engine.scan(scan_config).await?;
                
                info!("Success Scan complete!");
                info!("   Found {} findings", results.findings.len());
                info!("   Critical: {}", results.count_by_severity("critical"));
                info!("   High: {}", results.count_by_severity("high"));
                info!("   Medium: {}", results.count_by_severity("medium"));
                info!("   Low: {}", results.count_by_severity("low"));
            }
        }

        Commands::AI {
            target,
            output,
            validate,
            threshold,
            max_regions,
        } => {
            info!("AI Starting HyperionAI Analysis...");
            info!("Target: {}", target);
            info!("Exploit Validation: {}", validate);
            info!("Suspicion Threshold: {}", threshold);
            info!("Max LLM Regions: {}", max_regions);

            // Configure AI engine
            let ai_config = AIConfig {
                enable_ml_agents: true,
                enable_exploit_validation: validate,
                ollama_url: "http://localhost:11434".to_string(),
                suspicion_threshold: threshold,
                max_llm_regions: max_regions,
                python_path: std::path::PathBuf::from("python"),
            };

            let ai_engine = AIEngine::new(ai_config);
            let target_path = std::path::Path::new(&target);
            
            // Run AI analysis
            let ai_results = ai_engine.analyze(target_path).await?;
            
            // Save results
            let ai_json = serde_json::to_string_pretty(&ai_results)?;
            std::fs::write(&output, ai_json)?;
            
            info!("Success AI Analysis complete!");
            info!("   Results saved to: {:?}", output);
            info!("   Hunter regions: {}", ai_results.hunter_results.total_regions);
            info!("   High suspicion: {}", ai_results.hunter_results.high_suspicion_regions);
            
            if let Some(ref llm_results) = ai_results.llm_results {
                info!("   LLM confidence: {:.2}", llm_results.average_confidence);
            }
            
            if let Some(ref exploit_results) = ai_results.exploit_results {
                info!("   Exploits tested: {}", exploit_results.exploits_tested);
                info!("   Successful exploits: {}", exploit_results.successful_exploits);
                info!("   False positives eliminated: {}", exploit_results.false_positives_eliminated);
                info!("   Accuracy: {}%", exploit_results.accuracy_percentage);
            }
            
            info!("   Final findings: {}", ai_results.final_findings.len());
            info!("   Recommendation: {}", ai_results.final_findings.first()
                .map(|f| &f.severity).unwrap_or(&"None".to_string()));
        }

        Commands::Plugins { dir } => {
            println!("\nPackage Installed Plugins:\n");
            
            // Use plugin discovery to show all plugins with details
            let plugins = plugins::discover_plugins(&dir)?;
            
            if plugins.is_empty() {
                println!("  No plugins found in {:?}", dir);
                println!("  Plugins should have a plugin.toml manifest.");
            } else {
                for plugin in plugins {
                    let status = if plugin.is_enabled() { "Success" } else { "Failure" };
                    let enabled = if plugin.is_enabled() { "enabled" } else { "disabled" };
                    println!("  {} {} v{} [{}] - {}",
                        status,
                        plugin.name(),
                        plugin.manifest.plugin.version,
                        plugin.plugin_type(),
                        enabled
                    );
                    if !plugin.manifest.plugin.description.is_empty() {
                        println!("      {}", plugin.manifest.plugin.description);
                    }
                }
            }
            println!();
        }

        Commands::Report { dir, format } => {
            let report_path = dir.join(format!("last_scan.{}", format));
            
            if report_path.exists() {
                let content = std::fs::read_to_string(&report_path)?;
                println!("{}", content);
            } else {
                println!("No report found at {:?}", report_path);
                println!("Run a scan first: hyperion scan <path>");
            }
        }

        Commands::Pdf { dir, output } => {
            let json_path = dir.join("last_scan.json");
            
            if !json_path.exists() {
                println!("No scan results found. Run a scan first.");
                return Ok(());
            }

            let output_path = output.unwrap_or_else(|| dir.join("last_scan.pdf"));
            reports::generate_pdf(&json_path, &output_path)?;
            
            info!("Document PDF generated: {:?}", output_path);
        }

        Commands::Findings { dir, severity } => {
            let json_path = dir.join("last_scan.json");
            
            if !json_path.exists() {
                println!("No scan results found. Run a scan first.");
                return Ok(());
            }

            let results = reports::load_results(&json_path)?;
            
            println!("\nChecklist Scan Findings Summary\n");
            println!("═══════════════════════════════════════════════════════════\n");

            for finding in &results.findings {
                if let Some(ref sev) = severity {
                    if finding.severity.to_lowercase() != sev.to_lowercase() {
                        continue;
                    }
                }

                let icon = match finding.severity.to_lowercase().as_str() {
                    "critical" => "Critical",
                    "high" => "High",
                    "medium" => "Medium",
                    "low" => "Low",
                    _ => "Info",
                };

                println!("{} [{}] {}", icon, finding.severity.to_uppercase(), finding.id);
                println!("   File: {}:{}", finding.path, finding.line);
                println!("   {}\n", finding.message);
            }
        }

        Commands::Init { output } => {
            let default_config = Config::default();
            default_config.save(&output)?;
            info!("Success Configuration file created: {:?}", output);
        }
    }

    Ok(())
}
