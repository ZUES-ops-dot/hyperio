//! JSON report generator

use anyhow::Result;
use std::path::Path;
use super::ScanResults;

/// Generate JSON report
pub fn generate_json_report(results: &ScanResults, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Generate compact JSON (for automation)
pub fn generate_compact_json(results: &ScanResults, path: &Path) -> Result<()> {
    let json = serde_json::to_string(results)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Generate SARIF format (Static Analysis Results Interchange Format)
pub fn generate_sarif_report(results: &ScanResults, path: &Path) -> Result<()> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HyperionScan",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/hyperion-scan",
                    "rules": results.unique_rules().iter().map(|rule| {
                        serde_json::json!({
                            "id": rule,
                            "name": rule
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": results.findings.iter().map(|f| {
                serde_json::json!({
                    "ruleId": f.id,
                    "level": match f.severity.as_str() {
                        "critical" | "high" => "error",
                        "medium" => "warning",
                        _ => "note"
                    },
                    "message": {
                        "text": f.message
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.path
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column.max(1)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(path, json)?;
    Ok(())
}
