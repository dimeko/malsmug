use oxc::{ast::ast::{Argument, Expression, Program}, ast_visit::walk::walk_call_expression};
use oxc::{allocator::Allocator, ast::ast::CallExpression, ast::ast::BinaryExpression};
use oxc::parser::{
    Parser as JSParser, ParseOptions
};
use oxc::span::SourceType;
use oxc::ast_visit::{walk, Visit};

use crate::{analysis::analyzer::{self, Finding}, store::models::FileAnalysisReport};
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
struct Scanner {
    source: Vec<u8>,
    _interesting_items: Vec<StaticAnalysisIoC>
}

impl<'a> Visit<'a> for Scanner {
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
        // continue walking
        walk_call_expression(self, it);
    }
}

pub struct SastAnalyzer {}

impl SastAnalyzer {
    pub fn new() -> Self {
        SastAnalyzer {}
    }

    fn scan_ast(&mut self, source_code: Vec<u8>, ast: Program) -> Option<Vec<StaticAnalysisIoC>> {
        let mut scanner = Scanner { source: source_code, _interesting_items: Vec::new() };
        walk::walk_program::<Scanner>(&mut scanner, &ast);
        return Some(scanner._interesting_items);
    }
}

impl<'a> analyzer::SastAnalyze<'a> for SastAnalyzer {
    fn analyze(&mut self, file_report: FileAnalysisReport, source_code: Vec<u8>) -> Result<Vec<Finding>, String> {
        // analysis parameters preparation
        let mut findings: Vec<Finding> = Vec::new();
        let source_type: SourceType = SourceType::from_extension(&file_report.file_extension.as_str()).unwrap();
        let allocator = Allocator::default();

         let binding_vec = source_code.to_vec();
         let _src_str = match str::from_utf8(&binding_vec) {
            Ok(v) => v,
            Err(e) => {
                return Err(format!("could not parse source code bytes to string. Error: {:?}", e));
            }
        };
        let js_file_ast = JSParser::new(&allocator, _src_str, source_type)
            .with_options(ParseOptions { parse_regular_expression: true, ..ParseOptions::default() })
            .parse();
        // ---------------------------------------------------
        // static analysis steps

        // analyse the Abstract Syntax Tree (for now)
        let _interesting_findings_iter = &mut self.scan_ast(source_code, js_file_ast.program).unwrap();
        let mut _interesting_findings: Vec<analyzer::Finding> = _interesting_findings_iter.iter().map(|_it| {
            return analyzer::Finding {
                r#type: analyzer::AnalysisType::Static,
                executed_on: "".to_string(),
                poc: _it.poc.clone(),
                severity: _it.severity.clone(),
                title: _it.title.to_string()
            }
        }).collect();
        findings.append(&mut _interesting_findings);
        // ...
        // end of analysis
        // ---------------------------------------------------
        return Ok(findings);
    }
}