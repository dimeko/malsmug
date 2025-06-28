use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{analysis::dast_event_types, store::models::FileAnalysisReport};

#[allow(dead_code)]
#[repr(i64)]
#[derive(Deserialize, PartialEq, PartialOrd, Serialize, Debug)]
pub enum Severity {
    Low = 2,
    Moderate = 5,
    High = 8,
    VeryHigh = 10
}

impl Clone for Severity {
    fn clone(&self) -> Self {
        match self {
            Severity::Low => Severity::Low,
            Severity::Moderate => Severity::Moderate,
            Severity::High => Severity::High,
            Severity::VeryHigh => Severity::VeryHigh,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Moderate => write!(f, "Moderate"),
            Severity::High => write!(f, "High"),
            Severity::VeryHigh => write!(f, "Very High")
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub enum AnalysisType {
    Static,
    Dynamic
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Finding {
    pub r#type: AnalysisType,
    pub severity: Severity,
    pub poc: String,
    pub title: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("title: {}, severity: {}, poc: {}", self.title,  self.severity, self.poc))
    }
}

pub trait DastAnalyze<'a> {
    async fn analyze(&mut self, file_report: FileAnalysisReport, events: Vec<dast_event_types::Event>) -> Result<Vec<Finding>, String>;
}

pub trait SastAnalyze<'a> {
    fn analyze(&mut self, file_report: FileAnalysisReport, source_code: Vec<u8>) -> Result<Vec<Finding>, String>;
}