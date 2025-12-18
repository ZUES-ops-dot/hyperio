//! File system walker for source file discovery

use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use tracing::debug;

use crate::config::ScanSettings;
use super::language::{Language, LanguageDetector};

/// Represents a source file to be analyzed
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Absolute path to the file
    pub path: PathBuf,
    
    /// Relative path from scan root
    pub relative_path: PathBuf,
    
    /// Detected language
    pub language: Language,
    
    /// File contents
    pub content: String,
    
    /// File size in bytes
    pub size: usize,
    
    /// SHA256 hash of content
    pub hash: String,
}

/// Walks directories and collects source files
pub struct FileWalker {
    exclude_patterns: Vec<glob::Pattern>,
    max_file_size: usize,
    follow_symlinks: bool,
    language_detector: LanguageDetector,
}

impl FileWalker {
    /// Create a new file walker with scan settings
    pub fn new(settings: &ScanSettings) -> Self {
        let exclude_patterns: Vec<glob::Pattern> = settings
            .exclude
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            exclude_patterns,
            max_file_size: settings.max_file_size,
            follow_symlinks: settings.follow_symlinks,
            language_detector: LanguageDetector::new(&settings.languages),
        }
    }

    /// Collect all source files from a directory
    pub fn collect_files(&self, root: &Path) -> Result<Vec<SourceFile>> {
        let mut files = Vec::new();

        let walker = WalkDir::new(root)
            .follow_links(self.follow_symlinks)
            .into_iter()
            .filter_entry(|e| !self.is_excluded(e.path()));

        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            
            // Check file size
            if let Ok(metadata) = entry.metadata() {
                if metadata.len() as usize > self.max_file_size {
                    debug!("Skipping large file: {:?}", path);
                    continue;
                }
            }

            // Detect language
            if let Some(language) = self.language_detector.detect(path) {
                if let Ok(content) = std::fs::read_to_string(path) {
                    let hash = self.compute_hash(&content);
                    let relative_path = path.strip_prefix(root)
                        .unwrap_or(path)
                        .to_path_buf();

                    files.push(SourceFile {
                        path: path.to_path_buf(),
                        relative_path,
                        language,
                        size: content.len(),
                        content,
                        hash,
                    });
                }
            }
        }

        Ok(files)
    }

    /// Check if a path should be excluded
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        for pattern in &self.exclude_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
            
            // Also check just the file/dir name
            if let Some(name) = path.file_name() {
                if pattern.matches(&name.to_string_lossy()) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Compute SHA256 hash of content
    fn compute_hash(&self, content: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}
