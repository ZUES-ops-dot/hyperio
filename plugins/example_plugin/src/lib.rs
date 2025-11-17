//! Example HyperionScan WASM Plugin
//!
//! This is a template for creating custom security scanners.
//!
//! Build with:
//!   cargo build --target wasm32-wasi --release
//!
//! Then copy the .wasm file to the plugins directory.

use serde::{Deserialize, Serialize};

/// Input passed from the host
#[derive(Debug, Deserialize)]
struct PluginInput {
    language: String,
    path: String,
    source: String,
    ast: String,
    hash: String,
}

/// Finding to report
#[derive(Debug, Serialize)]
struct Finding {
    id: String,
    severity: String,
    message: String,
    line: usize,
    column: usize,
    rule_name: Option<String>,
    cwe: Option<String>,
    fix_suggestion: Option<String>,
    snippet: Option<String>,
    confidence: f64,
}

/// Output returned to the host
#[derive(Debug, Serialize)]
struct PluginOutput {
    findings: Vec<Finding>,
    metadata: std::collections::HashMap<String, String>,
    errors: Vec<String>,
}

/// Main analysis function - this is called by the host
///
/// # Safety
/// This function is called via FFI from the WASM host.
#[no_mangle]
pub extern "C" fn analyze(input_ptr: i32, input_len: i32) -> i32 {
    // In a real implementation, we would:
    // 1. Read input JSON from memory at input_ptr
    // 2. Parse the input
    // 3. Perform analysis
    // 4. Write output JSON to memory
    // 5. Return 0 for success, non-zero for error

    // This is a simplified example
    0
}

/// Analyze the source code for security issues
fn analyze_source(input: &PluginInput) -> PluginOutput {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    // Example: Check for dangerous patterns
    for (line_num, line) in input.source.lines().enumerate() {
        // Example check: Look for TODO comments
        if line.contains("TODO") || line.contains("FIXME") {
            findings.push(Finding {
                id: "EXAMPLE_TODO_001".to_string(),
                severity: "info".to_string(),
                message: "TODO/FIXME comment found".to_string(),
                line: line_num + 1,
                column: 0,
                rule_name: Some("Example Todo Check".to_string()),
                cwe: None,
                fix_suggestion: Some("Complete the TODO item".to_string()),
                snippet: Some(line.trim().to_string()),
                confidence: 1.0,
            });
        }

        // Example check: Look for hardcoded numbers that might be magic numbers
        if line.contains("1000000") || line.contains("1e18") {
            findings.push(Finding {
                id: "EXAMPLE_MAGIC_001".to_string(),
                severity: "low".to_string(),
                message: "Possible magic number - consider using a named constant".to_string(),
                line: line_num + 1,
                column: 0,
                rule_name: Some("Magic Number Check".to_string()),
                cwe: None,
                fix_suggestion: Some("Extract to a named constant".to_string()),
                snippet: Some(line.trim().to_string()),
                confidence: 0.7,
            });
        }
    }

    PluginOutput {
        findings,
        metadata: std::collections::HashMap::new(),
        errors,
    }
}

/// Memory allocation function for the host
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Memory deallocation function for the host
#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}
