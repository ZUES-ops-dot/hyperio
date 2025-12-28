//! Report generator coordinator

use anyhow::Result;
use std::path::Path;
use tracing::info;

use crate::config::ReportSettings;
use super::{ScanResults, json, markdown, pdf};

/// Report generator
pub struct ReportGenerator {
    include_snippets: bool,
    snippet_lines: usize,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(settings: &ReportSettings) -> Self {
        Self {
            include_snippets: settings.include_snippets,
            snippet_lines: settings.snippet_lines,
        }
    }

    /// Generate reports in specified formats
    pub fn generate(&self, results: &ScanResults, output_dir: &Path, formats: &[String]) -> Result<()> {
        // Ensure output directory exists
        std::fs::create_dir_all(output_dir)?;

        for format in formats {
            match format.to_lowercase().as_str() {
                "json" => {
                    let path = output_dir.join("last_scan.json");
                    json::generate_json_report(results, &path)?;
                    info!("Document Generated: {:?}", path);
                }
                "markdown" | "md" => {
                    let path = output_dir.join("last_scan.md");
                    markdown::generate_markdown_report(results, &path)?;
                    info!("Document Generated: {:?}", path);
                }
                "pdf" => {
                    let path = output_dir.join("last_scan.pdf");
                    pdf::generate_pdf_report(results, &path)?;
                    info!("Document Generated: {:?}", path);
                }
                "html" => {
                    let path = output_dir.join("last_scan.html");
                    self.generate_html(results, &path)?;
                    info!("Document Generated: {:?}", path);
                }
                _ => {
                    tracing::warn!("Unknown report format: {}", format);
                }
            }
        }

        // Also write trace log
        let trace_path = output_dir.join("trace.log");
        self.write_trace_log(results, &trace_path)?;

        Ok(())
    }

    /// Generate HTML report
    fn generate_html(&self, results: &ScanResults, path: &Path) -> Result<()> {
        let breakdown = results.severity_breakdown();
        
        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HyperionScan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 30px 0; }}
        .stat {{ flex: 1; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-critical {{ background: #fff5f5; border: 2px solid #dc3545; }}
        .stat-high {{ background: #fff8f0; border: 2px solid #fd7e14; }}
        .stat-medium {{ background: #fffbeb; border: 2px solid #ffc107; }}
        .stat-low {{ background: #f0fff4; border: 2px solid #28a745; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .finding {{ border: 1px solid #ddd; margin: 15px 0; border-radius: 8px; overflow: hidden; }}
        .finding-header {{ padding: 15px; display: flex; justify-content: space-between; align-items: center; }}
        .finding-header.critical {{ background: #dc3545; color: white; }}
        .finding-header.high {{ background: #fd7e14; color: white; }}
        .finding-header.medium {{ background: #ffc107; color: #333; }}
        .finding-header.low {{ background: #28a745; color: white; }}
        .finding-header.info {{ background: #6c757d; color: white; }}
        .finding-body {{ padding: 20px; }}
        .code {{ background: #f8f8f8; padding: 15px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
        .meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Shield️ HyperionScan Security Report</h1>
        
        <div class="meta">
            <p><strong>Scan ID:</strong> {}</p>
            <p><strong>Target:</strong> {}</p>
            <p><strong>Files Scanned:</strong> {}</p>
            <p><strong>Timestamp:</strong> {}</p>
        </div>

        <h2>Summary</h2>
        <div class="summary">
            <div class="stat stat-critical">
                <div class="stat-number">{}</div>
                <div>Critical</div>
            </div>
            <div class="stat stat-high">
                <div class="stat-number">{}</div>
                <div>High</div>
            </div>
            <div class="stat stat-medium">
                <div class="stat-number">{}</div>
                <div>Medium</div>
            </div>
            <div class="stat stat-low">
                <div class="stat-number">{}</div>
                <div>Low</div>
            </div>
        </div>

        <h2>Findings</h2>
        {}
    </div>
</body>
</html>"#,
            results.scan_id,
            results.target,
            results.files_scanned,
            results.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            breakdown.critical,
            breakdown.high,
            breakdown.medium,
            breakdown.low,
            self.findings_to_html(&results.findings)
        );

        std::fs::write(path, html)?;
        Ok(())
    }

    fn findings_to_html(&self, findings: &[super::Finding]) -> String {
        findings
            .iter()
            .map(|f| {
                let snippet_html = f.snippet
                    .as_ref()
                    .map(|s| format!("<div class=\"code\">{}</div>", html_escape(s)))
                    .unwrap_or_default();

                let fix_html = f.fix_suggestion
                    .as_ref()
                    .map(|s| format!("<p><strong>Fix:</strong> {}</p>", html_escape(s)))
                    .unwrap_or_default();

                format!(
                    r#"<div class="finding">
                        <div class="finding-header {}">
                            <span><strong>{}</strong> - {}</span>
                            <span>{}:{}</span>
                        </div>
                        <div class="finding-body">
                            <p>{}</p>
                            {}
                            {}
                        </div>
                    </div>"#,
                    f.severity.to_lowercase(),
                    f.id,
                    html_escape(&f.rule_name),
                    html_escape(&f.path),
                    f.line,
                    html_escape(&f.message),
                    snippet_html,
                    fix_html
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Write trace log
    fn write_trace_log(&self, results: &ScanResults, path: &Path) -> Result<()> {
        let mut log = String::new();
        
        log.push_str(&format!("HyperionScan Trace Log\n"));
        log.push_str(&format!("======================\n\n"));
        log.push_str(&format!("Scan ID: {}\n", results.scan_id));
        log.push_str(&format!("Target: {}\n", results.target));
        log.push_str(&format!("Timestamp: {}\n", results.timestamp));
        log.push_str(&format!("Files Scanned: {}\n", results.files_scanned));
        log.push_str(&format!("Total Findings: {}\n\n", results.findings.len()));

        log.push_str("Findings by Severity:\n");
        let breakdown = results.severity_breakdown();
        log.push_str(&format!("  Critical: {}\n", breakdown.critical));
        log.push_str(&format!("  High: {}\n", breakdown.high));
        log.push_str(&format!("  Medium: {}\n", breakdown.medium));
        log.push_str(&format!("  Low: {}\n", breakdown.low));
        log.push_str(&format!("  Info: {}\n\n", breakdown.info));

        log.push_str("Rules Triggered:\n");
        for rule in results.unique_rules() {
            log.push_str(&format!("  - {}\n", rule));
        }

        std::fs::write(path, log)?;
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
