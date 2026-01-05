//! ML-based anomaly detection (optional feature)
//!
//! This module provides placeholder for ONNX-based machine learning detection.
//! When ONNX support is needed, enable the ml feature and install ort crate.

use anyhow::Result;
use crate::core::SourceFile;
use crate::reports::Finding;
use tracing::warn;

/// Placeholder ML detector
/// 
/// When ML feature is fully implemented, this will use ONNX runtime
/// to run anomaly detection models locally.
pub struct MlDetector;

impl MlDetector {
    /// Load model from ONNX file (placeholder)
    pub fn load(_model_path: &str) -> Result<Self> {
        warn!("ML detection not yet implemented. This is a placeholder.");
        Ok(Self)
    }

    /// Detect anomalies in source files (placeholder)
    pub fn detect(&self, _files: &[SourceFile]) -> Result<Vec<Finding>> {
        // Future implementation would:
        // 1. Load ONNX model using ort crate
        // 2. Tokenize and embed source code
        // 3. Run inference
        // 4. Return findings for anomalous patterns
        Ok(vec![])
    }
}
