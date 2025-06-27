use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct FileAnalysisReport {
    pub uid: Option<String>,
    pub name: String,
    pub file_hash: String,
    pub file_name: String,
    pub file_extension: String,
    pub has_been_analysed: bool,
    pub severity: i64,
    pub analysis_report: String,
}

impl FileAnalysisReport {
    pub fn new(
        name: String,
        file_hash: String,
        file_name: String,
        file_extension: String,
        has_been_analysed: bool,
        severity: i64, analysis_report: String) -> Self {
          FileAnalysisReport {
            name,
            file_hash,
            file_name,
            file_extension,
            has_been_analysed,
            severity,
            analysis_report,
            uid: None
          }  
    }

    pub fn copy_no_uid(&self) -> FileAnalysisReport {
        FileAnalysisReport {
          uid: None,
          name: self.name.clone(),
          file_hash: self.file_hash.clone(),
          file_name: self.file_name.clone(),
          file_extension: self.file_extension.clone(),
          has_been_analysed: self.has_been_analysed.clone(),
          severity: self.severity.clone(),
          analysis_report: self.analysis_report.clone() 
      }
    }
}