//! Core engine module for HyperionScan
//!
//! This module contains the main scanning engine and supporting components.

mod engine;
mod file_walker;
mod language;
pub mod ast;
mod git;

pub use engine::Engine;
pub use file_walker::{FileWalker, SourceFile};
pub use language::{Language, LanguageDetector};
pub use ast::{AstParser, AstResult, SymbolKind};
pub use git::RepoCloner;
