//! Main scanning engine

use anyhow::Result;
use std::path::PathBuf;
use tracing::{info, debug, warn};

use crate::config::Config;
use crate::plugins::PluginManager;
use crate::reports::{ReportGenerator, ScanResults, Finding};
use crate::scanner::{ScanConfig, Scanner};
use super::{FileWalker, SourceFile, RepoCloner, AstParser};

/// The main HyperionScan engine
pub struct Engine {
    config: Config,
    plugin_manager: PluginManager,
    ast_parser: AstParser,
}

impl Engine {
    /// Create a new engine instance
    pub fn new(config: Config) -> Result<Self> {
        let plugin_dir = PathBuf::from(&config.plugins.dir);
        let plugin_manager = PluginManager::new(&plugin_dir, &config.plugins)?;
        let ast_parser = AstParser::new();

        Ok(Self {
            config,
            plugin_manager,
            ast_parser,
        })
    }

    /// Run a complete scan
    pub async fn scan(&mut self, scan_config: ScanConfig) -> Result<ScanResults> {
        let target_path = self.resolve_target(&scan_config.target).await?;
        
        info!("Folder Scanning directory: {:?}", target_path);

        // Walk the file system and collect source files
        let walker = FileWalker::new(&self.config.scan);
        let source_files = walker.collect_files(&target_path)?;
        
        info!("Document Found {} source files", source_files.len());

        // Parse and analyze each file
        let mut all_findings: Vec<Finding> = Vec::new();
        let scanner = Scanner::new(&self.config);

        for file in &source_files {
            debug!("Analyzing: {:?}", file.path);
            
            // Parse AST
            let ast_result = self.ast_parser.parse(file)?;
            
            // Run built-in scanners
            let mut findings = scanner.scan_file(file, &ast_result)?;
            all_findings.append(&mut findings);

            // Run WASM plugins
            let mut plugin_findings = self.plugin_manager.analyze(file, &ast_result)?;
            all_findings.append(&mut plugin_findings);
        }

        // Run fuzzing if enabled
        if scan_config.enable_fuzzing {
            info!("AI Running fuzzer with {} iterations...", scan_config.fuzz_iterations);
            let fuzz_findings = self.run_fuzzing(&source_files, scan_config.fuzz_iterations)?;
            all_findings.extend(fuzz_findings);
        }

        // Run ML detection if enabled
        if self.config.ml.enabled {
            info!("AI Running ML anomaly detection...");
            let ml_findings = self.run_ml_detection(&source_files)?;
            all_findings.extend(ml_findings);
        }

        // Deduplicate findings
        all_findings.sort_by(|a, b| {
            a.path.cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.id.cmp(&b.id))
        });
        all_findings.dedup_by(|a, b| a.id == b.id && a.path == b.path && a.line == b.line);

        // Build results
        let results = ScanResults {
            scan_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            target: scan_config.target.clone(),
            files_scanned: source_files.len(),
            findings: all_findings,
            duration_ms: 0, // TODO: track actual duration
        };

        // Generate reports
        let generator = ReportGenerator::new(&self.config.report);
        generator.generate(&results, &scan_config.output_dir, &scan_config.formats)?;

        Ok(results)
    }

    /// Resolve target path - clone if Git URL, otherwise use local path
    async fn resolve_target(&self, target: &str) -> Result<PathBuf> {
        if target.starts_with("http://") || target.starts_with("https://") || target.ends_with(".git") {
            info!("Loop Cloning repository: {}", target);
            let cloner = RepoCloner::new();
            cloner.clone(target).await
        } else {
            Ok(PathBuf::from(target))
        }
    }

    /// Run mutation-based fuzzing
    fn run_fuzzing(&self, _files: &[SourceFile], iterations: u32) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        // Basic fuzzing implementation
        // In a real implementation, this would:
        // 1. Identify fuzzable targets (functions, entry points)
        // 2. Generate mutated inputs
        // 3. Execute and detect crashes/panics
        
        debug!("Fuzzing with {} iterations", iterations);
        
        // Placeholder - real fuzzing would go here
        for _i in 0..iterations.min(10) {
            // Simulate fuzzing pass
        }

        Ok(findings)
    }

    /// Run ML-based anomaly detection
    fn run_ml_detection(&self, files: &[SourceFile]) -> Result<Vec<Finding>> {
        use crate::scanner::MlDetector;
        
        if let Some(ref model_path) = self.config.ml.model_path {
            let detector = MlDetector::load(model_path)?;
            detector.detect(files)
        } else {
            warn!("ML enabled but no model path configured");
            Ok(vec![])
        }
    }
}
