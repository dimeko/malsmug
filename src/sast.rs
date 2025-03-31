use std::{fs::File, io::Read, path::{Path, PathBuf}};
use log::error;

use oxc::{ast::ast::{Argument, Expression, Program}, ast_visit::walk::walk_call_expression};
use oxc::{allocator::Allocator, ast::ast::CallExpression, ast::ast::BinaryExpression};
use oxc::parser::{
    Parser as JSParser, ParseOptions
};
use oxc::span::SourceType;
use oxc::ast_visit::{walk, Visit};

use crate::analyzer;
use crate::utils;
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
                        severity: analyzer::Severity::High,
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

                        if utils::contains_html_like_code(resolved_binary_expression.as_str()){
                            self._interesting_items.push(
                                StaticAnalysisIoC {
                                    severity: analyzer::Severity::Moderate,
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
}

pub struct SastAnalyzer {
    source_text: String,
    file_path: PathBuf,
    findings: Vec<analyzer::Finding>
}

impl SastAnalyzer {
    pub fn new(file_path: PathBuf) -> Self {
        let mut _f = match File::open(&file_path) {
            Ok(_f) => _f,
            Err(_e) => {
                error!("error opening {}: {}", file_path.to_string_lossy(), _e);
                std::process::exit(1)
            }
        };

        let mut _str_from_file = String::new();
        let _string = _f.read_to_string(&mut _str_from_file).unwrap();

        SastAnalyzer {
            file_path,
            source_text: _str_from_file,
            findings: Vec::new()
        }
    }

    fn _scan_ast(&mut self, ast: Program) -> Vec<StaticAnalysisIoC> {

        let mut scanner = Scanner { source: &self.source_text, _interesting_items: Vec::new() };
        walk::walk_program::<Scanner>(&mut scanner, &ast);
        return scanner._interesting_items
    }

    fn get_src_text(&self) -> String {
        self.source_text.clone()
    }
}

impl<'a> analyzer::Analyzer<'a> for SastAnalyzer {
    fn analyze(&mut self) -> Result<bool, String> {
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
        let _interesting_findings = &mut self._scan_ast(js_file_ast.program).iter().map(|_it| {
            return analyzer::Finding {
                poc: _it.poc.clone(),
                severity: _it.severity.clone(),
                title: _it.title.to_string()
            }
        }).collect();
        self.findings.append(_interesting_findings);
        // ...
        // end of analysis
        // ---------------------------------------------------
        return Ok(true);
    }

    fn get_findings(&self) -> &Vec<analyzer::Finding> {
        &self.findings
    }
}