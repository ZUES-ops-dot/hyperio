//! Report generation module

mod finding;
mod generator;
mod json;
mod markdown;
mod pdf;

pub use finding::{Finding, ScanResults};
pub use generator::ReportGenerator;

use anyhow::Result;
use std::path::Path;

/// Load scan results from JSON file
pub fn load_results(path: &Path) -> Result<ScanResults> {
    let content = std::fs::read_to_string(path)?;
    let results: ScanResults = serde_json::from_str(&content)?;
    Ok(results)
}

/// Generate PDF from JSON results
pub fn generate_pdf(json_path: &Path, output_path: &Path) -> Result<()> {
    let results = load_results(json_path)?;
    pdf::generate_pdf_report(&results, output_path)
}
