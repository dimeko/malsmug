use oxc::ast::ast::Program;
use std::{fs::File, io::Read, path::{Path, PathBuf}};
use oxc::{allocator::Allocator, ast::ast::{Expression, Function, match_member_expression}};
use oxc::parser::{
    Parser as JSParser, ParseOptions
};
use oxc::span::SourceType;
use oxc::ast_visit::{walk, Visit};

use crate::analyzer::{self, Finding};

// creating different struct here in order to be able to create
// multiple sources for [`analyzer::Findings`]
struct IoC {
    severity: analyzer::Severity,
    poc: String,
    title: String,
}

struct Scanner<'a> {
    source: &'a str,
    _interesting_items: Vec<IoC>
}

impl<'a> Visit<'a> for Scanner<'a> {
    fn visit_expression(&mut self, expr: &Expression) {
        if let Expression::CallExpression(_f) = expr {
            if let Expression::StaticMemberExpression(_m) = &_f.callee {
                if let Expression::Identifier(_id) = &_m.object {
                     if matches!(_id.name.as_str(), "xhr" | "eval" | "Function" | "setTimeout" | "setInterval") {
                        self._interesting_items.push(
                            IoC {
                                severity: analyzer::Severity::Moderate,
                                poc: _id.name.to_string(),
                                title: _id.name.to_string()
                            }
                        );
                    }
                }
            }
        }

        // if let Expression::FunctionExpression(_f) = expr {
        //     println!("FunctionExpression {:#?}", _f);
        // }
    }
}

pub struct SastAnalyzer {
    source_text: String,
    file_path: PathBuf,
    findings: Vec<analyzer::Finding>
}

impl SastAnalyzer {
    pub fn new(file_path: PathBuf) -> Self {
        let mut _f = File::open(&file_path).expect("could not open file");

        
        let mut _str_from_file = String::new();
        let _string = _f.read_to_string(&mut _str_from_file).unwrap();

        SastAnalyzer {
            file_path,
            source_text: _str_from_file,
            findings: Vec::new()
        }
    }

    fn _scan_ast(&mut self, ast: Program) {

        let mut scanner = Scanner { source: &self.source_text, _interesting_items: Vec::new() };
        walk::walk_program::<Scanner>(&mut scanner, &ast);

        self.findings = scanner._interesting_items.iter().map(|_it| {
            return analyzer::Finding {
                poc: _it.poc.clone(),
                severity: _it.severity.clone(),
            }
        }).collect();
    }

    fn get_src_text(&self) -> String {
        self.source_text.clone()
    }
}

impl<'a> analyzer::Analyzer<'a> for SastAnalyzer {
    fn analyze(&mut self) -> Result<bool, String> {
        let source_type: SourceType = SourceType::from_path(Path::new(&self.file_path)).unwrap();
        let allocator = Allocator::default();
        let binding = self.get_src_text(); // < ---------------------- be careful here
        let _src_str = &binding.as_str(); // review this
        let js_file_ast = JSParser::new(&allocator, _src_str, source_type)
            .with_options(ParseOptions { parse_regular_expression: true, ..ParseOptions::default() })
            .parse();
        self._scan_ast(js_file_ast.program);
        return Ok(true);
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}