//! AST parsing using tree-sitter

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tree_sitter::{Parser, Tree, Node};
use tracing::debug;

use super::{SourceFile, Language};

/// Result of AST parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstResult {
    /// Language of the parsed file
    pub language: Language,
    
    /// Whether parsing was successful
    pub success: bool,
    
    /// Serialized AST (simplified representation)
    pub ast_json: String,
    
    /// Extracted symbols (functions, contracts, etc.)
    pub symbols: Vec<Symbol>,
    
    /// Syntax errors found during parsing
    pub errors: Vec<SyntaxError>,
}

/// A symbol extracted from the AST
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    
    /// Symbol kind (function, contract, struct, etc.)
    pub kind: SymbolKind,
    
    /// Start line
    pub start_line: usize,
    
    /// End line
    pub end_line: usize,
    
    /// Visibility (public, private, internal, external)
    pub visibility: Option<String>,
    
    /// Modifiers or attributes
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    Function,
    Contract,
    Struct,
    Enum,
    Event,
    Modifier,
    Variable,
    Import,
    Module,
    Trait,
    Impl,
}

/// A syntax error in the source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntaxError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

/// AST Parser using tree-sitter
pub struct AstParser {
    rust_parser: Option<Parser>,
    js_parser: Option<Parser>,
    ts_parser: Option<Parser>,
}

impl AstParser {
    /// Create a new AST parser
    pub fn new() -> Self {
        let mut rust_parser = Parser::new();
        let rust_lang = tree_sitter_rust::language();
        if rust_parser.set_language(rust_lang).is_err() {
            debug!("Failed to set Rust language");
        }

        let mut js_parser = Parser::new();
        let js_lang = tree_sitter_javascript::language();
        if js_parser.set_language(js_lang).is_err() {
            debug!("Failed to set JavaScript language");
        }

        let mut ts_parser = Parser::new();
        let ts_lang = tree_sitter_typescript::language_typescript();
        if ts_parser.set_language(ts_lang).is_err() {
            debug!("Failed to set TypeScript language");
        }

        Self {
            rust_parser: Some(rust_parser),
            js_parser: Some(js_parser),
            ts_parser: Some(ts_parser),
        }
    }

    /// Parse a source file
    pub fn parse(&mut self, file: &SourceFile) -> Result<AstResult> {
        match file.language {
            Language::Rust => self.parse_rust(file),
            Language::JavaScript => self.parse_javascript(file),
            Language::TypeScript => self.parse_typescript(file),
            Language::Solidity => self.parse_solidity(file),
            _ => self.parse_fallback(file),
        }
    }

    fn parse_rust(&mut self, file: &SourceFile) -> Result<AstResult> {
        let parser = self.rust_parser.as_mut().unwrap();
        let tree = parser.parse(&file.content, None);
        
        self.process_tree(file, tree)
    }

    fn parse_javascript(&mut self, file: &SourceFile) -> Result<AstResult> {
        let parser = self.js_parser.as_mut().unwrap();
        let tree = parser.parse(&file.content, None);
        
        self.process_tree(file, tree)
    }

    fn parse_typescript(&mut self, file: &SourceFile) -> Result<AstResult> {
        let parser = self.ts_parser.as_mut().unwrap();
        let tree = parser.parse(&file.content, None);
        
        self.process_tree(file, tree)
    }

    /// Parse Solidity using pattern-based parsing (no tree-sitter grammar)
    fn parse_solidity(&self, file: &SourceFile) -> Result<AstResult> {
        let mut symbols = Vec::new();
        let mut errors = Vec::new();

        let lines: Vec<&str> = file.content.lines().collect();
        
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Contract detection
            if trimmed.starts_with("contract ") || trimmed.starts_with("abstract contract ") {
                if let Some(name) = extract_identifier(trimmed, "contract ") {
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Contract,
                        start_line: i + 1,
                        end_line: i + 1, // TODO: find closing brace
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }
            
            // Function detection
            if trimmed.starts_with("function ") {
                if let Some(name) = extract_identifier(trimmed, "function ") {
                    let visibility = extract_visibility(trimmed);
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        start_line: i + 1,
                        end_line: i + 1,
                        visibility,
                        modifiers: extract_modifiers(trimmed),
                    });
                }
            }

            // Event detection
            if trimmed.starts_with("event ") {
                if let Some(name) = extract_identifier(trimmed, "event ") {
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Event,
                        start_line: i + 1,
                        end_line: i + 1,
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }

            // Modifier detection
            if trimmed.starts_with("modifier ") {
                if let Some(name) = extract_identifier(trimmed, "modifier ") {
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Modifier,
                        start_line: i + 1,
                        end_line: i + 1,
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }
        }

        Ok(AstResult {
            language: file.language,
            success: true,
            ast_json: serde_json::json!({
                "type": "solidity",
                "symbols": symbols.len()
            }).to_string(),
            symbols,
            errors,
        })
    }

    /// Fallback parser for unsupported languages
    fn parse_fallback(&self, file: &SourceFile) -> Result<AstResult> {
        Ok(AstResult {
            language: file.language,
            success: false,
            ast_json: "{}".to_string(),
            symbols: vec![],
            errors: vec![SyntaxError {
                line: 0,
                column: 0,
                message: format!("No parser available for {:?}", file.language),
            }],
        })
    }

    fn process_tree(&self, file: &SourceFile, tree: Option<Tree>) -> Result<AstResult> {
        let Some(tree) = tree else {
            return Ok(AstResult {
                language: file.language,
                success: false,
                ast_json: "{}".to_string(),
                symbols: vec![],
                errors: vec![SyntaxError {
                    line: 0,
                    column: 0,
                    message: "Failed to parse".to_string(),
                }],
            });
        };

        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut errors = Vec::new();

        // Collect errors
        self.collect_errors(&root, &mut errors);
        
        // Extract symbols
        self.extract_symbols(&root, &file.content, &mut symbols);

        // Serialize AST to JSON (simplified)
        let ast_json = self.serialize_node(&root, &file.content, 0);

        Ok(AstResult {
            language: file.language,
            success: errors.is_empty(),
            ast_json,
            symbols,
            errors,
        })
    }

    fn collect_errors(&self, node: &Node, errors: &mut Vec<SyntaxError>) {
        if node.is_error() || node.is_missing() {
            errors.push(SyntaxError {
                line: node.start_position().row + 1,
                column: node.start_position().column,
                message: format!("Syntax error: {}", node.kind()),
            });
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_errors(&child, errors);
        }
    }

    fn extract_symbols(&self, node: &Node, source: &str, symbols: &mut Vec<Symbol>) {
        let kind = node.kind();
        
        match kind {
            "function_item" | "function_definition" | "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        start_line: node.start_position().row + 1,
                        end_line: node.end_position().row + 1,
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }
            "struct_item" | "struct_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Struct,
                        start_line: node.start_position().row + 1,
                        end_line: node.end_position().row + 1,
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }
            "impl_item" => {
                symbols.push(Symbol {
                    name: "impl".to_string(),
                    kind: SymbolKind::Impl,
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    visibility: None,
                    modifiers: vec![],
                });
            }
            "trait_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Trait,
                        start_line: node.start_position().row + 1,
                        end_line: node.end_position().row + 1,
                        visibility: None,
                        modifiers: vec![],
                    });
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_symbols(&child, source, symbols);
        }
    }

    fn serialize_node(&self, node: &Node, source: &str, depth: usize) -> String {
        if depth > 10 {
            return "{}".to_string();
        }

        let mut children = Vec::new();
        let mut cursor = node.walk();
        
        for child in node.children(&mut cursor) {
            if depth < 5 {
                children.push(self.serialize_node(&child, source, depth + 1));
            }
        }

        serde_json::json!({
            "type": node.kind(),
            "start": [node.start_position().row, node.start_position().column],
            "end": [node.end_position().row, node.end_position().column],
            "children_count": node.child_count()
        }).to_string()
    }
}

// Helper functions for Solidity parsing
fn extract_identifier(line: &str, prefix: &str) -> Option<String> {
    let after_prefix = line.strip_prefix(prefix)?;
    let name: String = after_prefix
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_visibility(line: &str) -> Option<String> {
    for vis in &["public", "private", "internal", "external"] {
        if line.contains(vis) {
            return Some(vis.to_string());
        }
    }
    None
}

fn extract_modifiers(line: &str) -> Vec<String> {
    let mut modifiers = Vec::new();
    
    for modifier in &["view", "pure", "payable", "nonpayable", "virtual", "override"] {
        if line.contains(modifier) {
            modifiers.push(modifier.to_string());
        }
    }
    
    modifiers
}
