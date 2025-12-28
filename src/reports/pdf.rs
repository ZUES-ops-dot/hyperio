//! PDF report generator using printpdf

use anyhow::Result;
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use super::ScanResults;

/// Generate PDF report
pub fn generate_pdf_report(results: &ScanResults, path: &Path) -> Result<()> {
    // Create PDF document
    let (doc, page1, layer1) = PdfDocument::new(
        "HyperionScan Security Report",
        Mm(210.0),  // A4 width
        Mm(297.0),  // A4 height
        "Layer 1"
    );

    let current_layer = doc.get_page(page1).get_layer(layer1);
    
    // Load a font (using built-in for simplicity)
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

    let mut y_position = Mm(280.0);
    let left_margin = Mm(20.0);
    let line_height = Mm(6.0);

    // Title
    current_layer.use_text(
        "HyperionScan Security Report",
        24.0,
        left_margin,
        y_position,
        &font_bold
    );
    y_position -= Mm(15.0);

    // Separator line
    let line = Line {
        points: vec![
            (Point::new(left_margin, y_position), false),
            (Point::new(Mm(190.0), y_position), false),
        ],
        is_closed: false,
    };
    current_layer.add_line(line);
    y_position -= Mm(10.0);

    // Scan info
    current_layer.use_text(
        &format!("Scan ID: {}", results.scan_id),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= line_height;

    current_layer.use_text(
        &format!("Target: {}", results.target),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= line_height;

    current_layer.use_text(
        &format!("Date: {}", results.timestamp.format("%Y-%m-%d %H:%M:%S UTC")),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= line_height;

    current_layer.use_text(
        &format!("Files Scanned: {}", results.files_scanned),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= Mm(15.0);

    // Summary section
    current_layer.use_text(
        "Summary",
        14.0,
        left_margin,
        y_position,
        &font_bold
    );
    y_position -= Mm(10.0);

    let breakdown = results.severity_breakdown();
    
    current_layer.use_text(
        &format!("Total Findings: {}", breakdown.total()),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= line_height;

    current_layer.use_text(
        &format!("Critical: {}  |  High: {}  |  Medium: {}  |  Low: {}  |  Info: {}",
            breakdown.critical, breakdown.high, breakdown.medium, breakdown.low, breakdown.info),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= line_height;

    current_layer.use_text(
        &format!("Risk Score: {}/100", results.risk_score()),
        10.0,
        left_margin,
        y_position,
        &font
    );
    y_position -= Mm(15.0);

    // Findings section
    current_layer.use_text(
        "Findings",
        14.0,
        left_margin,
        y_position,
        &font_bold
    );
    y_position -= Mm(10.0);

    // Add findings (limited to first 20 for PDF size)
    let max_findings = 20;
    for (i, finding) in results.findings.iter().take(max_findings).enumerate() {
        // Check if we need a new page
        if y_position < Mm(30.0) {
            // Would need to add new page here - simplified for now
            current_layer.use_text(
                &format!("... and {} more findings (see JSON/MD report)",
                    results.findings.len() - i),
                10.0,
                left_margin,
                y_position,
                &font
            );
            break;
        }

        let severity_str = match finding.severity.as_str() {
            "critical" => "[CRITICAL]",
            "high" => "[HIGH]",
            "medium" => "[MEDIUM]",
            "low" => "[LOW]",
            _ => "[INFO]",
        };

        current_layer.use_text(
            &format!("{} {} - {}", severity_str, finding.id, finding.rule_name),
            9.0,
            left_margin,
            y_position,
            &font_bold
        );
        y_position -= line_height;

        current_layer.use_text(
            &format!("  File: {}:{}", finding.path, finding.line),
            8.0,
            left_margin,
            y_position,
            &font
        );
        y_position -= line_height;

        // Truncate message for PDF
        let msg = if finding.message.len() > 80 {
            format!("{}...", &finding.message[..80])
        } else {
            finding.message.clone()
        };
        
        current_layer.use_text(
            &format!("  {}", msg),
            8.0,
            left_margin,
            y_position,
            &font
        );
        y_position -= Mm(8.0);
    }

    // Footer
    y_position = Mm(15.0);
    current_layer.use_text(
        "Generated by HyperionScan - Local Security Scanner",
        8.0,
        left_margin,
        y_position,
        &font
    );

    // Save PDF
    let file = File::create(path)?;
    doc.save(&mut BufWriter::new(file))?;

    Ok(())
}
