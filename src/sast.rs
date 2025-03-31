use std::{fs::File, io::Read, path::{Path, PathBuf}};
use clap::Arg;
use regex::Regex;

use oxc::{ast::ast::{Argument, ComputedMemberExpression, Expression, PrivateFieldExpression, Program}, ast_visit::walk::{walk_binary_expression, walk_call_expression}};
use oxc::{allocator::Allocator, ast::ast::CallExpression, ast::ast::BinaryExpression};
use oxc::parser::{
    Parser as JSParser, ParseOptions
};
use oxc::allocator::Box;
use oxc::span::SourceType;
use oxc::ast_visit::{walk, Visit};

use crate::analyzer;

// creating different struct here in order to be able to create
// multiple sources for [`analyzer::Findings`]
struct StaticAnalysisIoC {
    severity: analyzer::Severity,
    poc: String,
    title: &'static str,
}

enum BinaryExpressionMemberType {
    StrLiteral,
    Variable,
    Unresolved
}

struct BinaryExpressionMember {
    value: String,
    expression_type: BinaryExpressionMemberType
}

// Utility function that let's resolve binary expressions (e.g. "exec" + "Script")
// This enables us to detect soft obfuscation techniques that are based on string literals
// concatenation 
fn binary_expression_resolver(expr: &BinaryExpression) -> Vec<BinaryExpressionMember> {
    let mut _binary_members: Vec<BinaryExpressionMember> = Vec::new();
    match &expr.left {
        Expression::BinaryExpression(_binexpr) => {
            _binary_members.append(&mut binary_expression_resolver(&_binexpr));
        },
        Expression::StringLiteral(_strexpr) => {
            _binary_members.push(BinaryExpressionMember {
                value: _strexpr.value.to_string(),
                expression_type: BinaryExpressionMemberType::StrLiteral
            });
        },
        Expression::Identifier(_idsxpr) => {
            _binary_members.push(BinaryExpressionMember {
                value: _idsxpr.to_string(),
                expression_type: BinaryExpressionMemberType::Variable
            });
        },
        _ => {
            _binary_members.push(BinaryExpressionMember {
                value: "".to_string(),
                expression_type: BinaryExpressionMemberType::Unresolved
            });
        }
    }
    match &expr.right {
        Expression::BinaryExpression(_binexpr) => {
            _binary_members.append(&mut binary_expression_resolver(&_binexpr));
        },
        Expression::StringLiteral(_strexpr) => {
            _binary_members.push(BinaryExpressionMember {
                value: _strexpr.value.to_string(),
                expression_type: BinaryExpressionMemberType::StrLiteral
            });
        },
        Expression::Identifier(_idsxpr) => {
            _binary_members.push(BinaryExpressionMember {
                value: _idsxpr.to_string(),
                expression_type: BinaryExpressionMemberType::Variable
            });
        },
        _ => {
            _binary_members.push(BinaryExpressionMember {
                value: "".to_string(),
                expression_type: BinaryExpressionMemberType::Unresolved
            });
        }
    }
    return _binary_members;
}

fn contains_html_like_code(input: &str) -> bool {
    let html_regex = Regex::new(r"<\s*!?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>|</\s*[a-zA-Z][a-zA-Z0-9]*\s*>").unwrap();
    html_regex.is_match(input)
}

struct Scanner<'a> {
    source: &'a str,
    _interesting_items: Vec<StaticAnalysisIoC>
}

impl<'a> Visit<'a> for Scanner<'a> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::StaticMemberExpression(_c) = &it.callee { // rule for file1
            if matches!(_c.property.name.as_str(), "eval" | "execScript") {
                self._interesting_items.push(
                    StaticAnalysisIoC {
                        severity: analyzer::Severity::VeryHigh,
                        poc: _c.property.name.to_string(),
                        title: "execution of known suspicious commands"
                })
            } else if let Expression::Identifier(_id) = &_c.object { // rule for file1
                if matches!(_c.property.name.as_str(), "write") && matches!(_id.name.as_str(), "document") {
                    for _arg in &it.arguments {
                        let mut resolved_binary_expression = String::new();

                        if let Argument::BinaryExpression(_binexpr) = &_arg {
                            let binary_expression_members: Vec<BinaryExpressionMember> = binary_expression_resolver(_binexpr);
                            
                            for _bm in binary_expression_members {
                                resolved_binary_expression.push_str(_bm.value.as_str());
                            }

                        } else if let Argument::StringLiteral(_strlit) = &_arg {
                            resolved_binary_expression.push_str(&_strlit.value);
                        }

                        if contains_html_like_code(resolved_binary_expression.as_str()){
                            self._interesting_items.push(
                                StaticAnalysisIoC {
                                    severity: analyzer::Severity::VeryHigh,
                                    poc: resolved_binary_expression,
                                    title: "html element adhoc write to dom"
                            });
                        }
                    }
                }
            }
        }
        // continue walking in case we want to hook for visitors
        walk_call_expression(self, it);
    }

    // check all resolved string of the script (it does not work very well as it resolves many duplicates)
    // fn visit_binary_expression(&mut self, it: &BinaryExpression<'a>) {
    //     let binary_expression_members: Vec<BinaryExpressionMember> = binary_expression_resolver(it);
    //     for _be in binary_expression_members.iter() {
    //         print!("{}", _be.value)
    //     }
    //     println!();
    //     walk_binary_expression(self, it);
    // }

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
                title: _it.title.to_string()
            }
        }).collect();
    }

    fn get_src_text(&self) -> String {
        self.source_text.clone()
    }
}

impl<'a> analyzer::Analyzer<'a> for SastAnalyzer {
    async fn analyze(&mut self) -> Result<bool, String> {
        // analysis parameters preparation
        let source_type: SourceType = SourceType::from_path(Path::new(&self.file_path)).unwrap();
        let allocator = Allocator::default();
        let binding = self.get_src_text();
        let _src_str = &binding.as_str();
        let js_file_ast = JSParser::new(&allocator, _src_str, source_type)
            .with_options(ParseOptions { parse_regular_expression: true, ..ParseOptions::default() })
            .parse();
        // ---------------------------------------------------
        // static analysis steps

        // analyse the Abstract Syntax Tree (for now)
        self._scan_ast(js_file_ast.program);
        // ...
        // end of analysis
        // ---------------------------------------------------
        return Ok(true);
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}