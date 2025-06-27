use core::fmt;

#[allow(dead_code)]
pub enum Severity {
    Low,
    Moderate,
    High,
    VeryHigh
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

#[derive(Clone)]
pub struct Finding {
    pub severity: Severity,
    pub poc: String,
    pub title: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("title: {}, severity: {}, poc: {}", self.title,  self.severity, self.poc))
    }
}

pub trait Analyzer<'a> {
    fn get_findings(&self, file_hash: String) -> Option<&Vec<Finding>>;
    fn analyze(&mut self, file_hash: String) -> Result<bool, String>;
}