//! Finding and scan result structures

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding identifier
    pub id: String,
    
    /// Severity level: critical, high, medium, low, info
    pub severity: String,
    
    /// Description of the finding
    pub message: String,
    
    /// File path (relative)
    pub path: String,
    
    /// Line number (1-indexed)
    pub line: usize,
    
    /// Column number (0-indexed)
    pub column: usize,
    
    /// Code snippet showing the issue
    pub snippet: Option<String>,
    
    /// Rule or check name
    pub rule_name: String,
    
    /// Category (solidity, rust, secrets, etc.)
    pub category: String,
    
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    
    /// CWE identifier if applicable
    pub cwe: Option<String>,
    
    /// Suggested fix
    pub fix_suggestion: Option<String>,
}

/// Results of a complete scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Unique scan identifier
    pub scan_id: String,
    
    /// Timestamp of the scan
    pub timestamp: DateTime<Utc>,
    
    /// Target that was scanned
    pub target: String,
    
    /// Number of files scanned
    pub files_scanned: usize,
    
    /// All findings
    pub findings: Vec<Finding>,
    
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

impl ScanResults {
    /// Count findings by severity
    pub fn count_by_severity(&self, severity: &str) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity.to_lowercase() == severity.to_lowercase())
            .count()
    }

    /// Count findings by category
    pub fn count_by_category(&self, category: &str) -> usize {
        self.findings
            .iter()
            .filter(|f| f.category.to_lowercase() == category.to_lowercase())
            .count()
    }

    /// Get severity breakdown
    pub fn severity_breakdown(&self) -> SeverityBreakdown {
        SeverityBreakdown {
            critical: self.count_by_severity("critical"),
            high: self.count_by_severity("high"),
            medium: self.count_by_severity("medium"),
            low: self.count_by_severity("low"),
            info: self.count_by_severity("info"),
        }
    }

    /// Get category breakdown
    pub fn category_breakdown(&self) -> std::collections::HashMap<String, usize> {
        let mut breakdown = std::collections::HashMap::new();
        
        for finding in &self.findings {
            *breakdown.entry(finding.category.clone()).or_insert(0) += 1;
        }
        
        breakdown
    }

    /// Get unique rules triggered
    pub fn unique_rules(&self) -> Vec<String> {
        let mut rules: Vec<String> = self.findings
            .iter()
            .map(|f| f.rule_name.clone())
            .collect();
        rules.sort();
        rules.dedup();
        rules
    }

    /// Filter findings by severity
    pub fn filter_by_severity(&self, min_severity: &str) -> Vec<&Finding> {
        let min_level = severity_to_level(min_severity);
        
        self.findings
            .iter()
            .filter(|f| severity_to_level(&f.severity) >= min_level)
            .collect()
    }

    /// Get risk score (0-100)
    pub fn risk_score(&self) -> u32 {
        let breakdown = self.severity_breakdown();
        
        let score = (breakdown.critical * 25)
            + (breakdown.high * 15)
            + (breakdown.medium * 8)
            + (breakdown.low * 3)
            + (breakdown.info * 1);
        
        score.min(100) as u32
    }
}

/// Severity breakdown counts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityBreakdown {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// Convert severity string to numeric level
fn severity_to_level(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

impl Finding {
    /// Get severity icon
    pub fn severity_icon(&self) -> &str {
        match self.severity.to_lowercase().as_str() {
            "critical" => "Critical",
            "high" => "High",
            "medium" => "Medium",
            "low" => "Low",
            "info" => "Info",
            _ => "None",
        }
    }

    /// Get severity color (for HTML/terminal)
    pub fn severity_color(&self) -> &str {
        match self.severity.to_lowercase().as_str() {
            "critical" => "#dc3545",
            "high" => "#fd7e14",
            "medium" => "#ffc107",
            "low" => "#28a745",
            "info" => "#6c757d",
            _ => "#000000",
        }
    }

    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("### {} [{}] {}\n\n", 
            self.severity_icon(), 
            self.severity.to_uppercase(), 
            self.id
        ));
        
        md.push_str(&format!("**File:** `{}` (line {})\n\n", self.path, self.line));
        md.push_str(&format!("**Rule:** {}\n\n", self.rule_name));
        md.push_str(&format!("{}\n\n", self.message));
        
        if let Some(ref snippet) = self.snippet {
            md.push_str("```\n");
            md.push_str(snippet);
            md.push_str("\n```\n\n");
        }
        
        if let Some(ref cwe) = self.cwe {
            md.push_str(&format!("**CWE:** {}\n\n", cwe));
        }
        
        if let Some(ref fix) = self.fix_suggestion {
            md.push_str(&format!("**Fix:** {}\n\n", fix));
        }
        
        md.push_str("---\n\n");
        md
    }
}
