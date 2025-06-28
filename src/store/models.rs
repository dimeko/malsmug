use log::debug;
use serde::{Deserialize, Serialize};
use crate::{analysis::analyzer::Finding, store::sqlite::FileAnalysisReportRaw};

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct FileAnalysisReport {
    pub uid: Option<String>,
    pub name: String,
    pub file_hash: String,
    pub file_name: String,
    pub file_extension: String,
    pub last_analysis_id: String,
    pub has_been_analysed: bool,
    pub dynamic_analysis: bool, 
    pub static_analysis: bool,
    pub severity: i64,
    pub bait_websites: Vec<String>,
    pub findings: Vec<Finding>,
}

impl FileAnalysisReport {
    pub fn new(
        name: String,
        file_hash: String,
        file_name: String,
        file_extension: String,
        last_analysis_id: String,
        has_been_analysed: bool,
        dynamic_analysis: bool, static_analysis: bool,
        severity: i64, bait_websites: Vec<String>, findings: Vec<Finding>) -> Self {
          FileAnalysisReport {
            name,
            file_hash,
            file_name,
            file_extension,
            last_analysis_id,
            has_been_analysed,
            dynamic_analysis,
            static_analysis,
            severity,
            findings,
            bait_websites,
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
          last_analysis_id: self.last_analysis_id.clone(),
          has_been_analysed: self.has_been_analysed.clone(),
          dynamic_analysis: self.dynamic_analysis.clone(),
          static_analysis: self.static_analysis.clone(),
          severity: self.severity.clone(),
          bait_websites: self.bait_websites.clone(),
          findings: self.findings.clone() 
      }
    }
}

impl From<FileAnalysisReportRaw> for FileAnalysisReport {
  fn from(raw: FileAnalysisReportRaw) -> Self {
        let bait_websites_from_raw: Vec<String> = raw.bait_websites.split(",").map(|s| s.to_string()).collect();
        let findings_from_raw: Vec<Finding> = match serde_json::from_str(raw.findings.as_str()) {
            Ok(r) => r,
            Err(e) => {
              debug!("ERROR: could not convert string findings to json: error: {:?}", e);
              Vec::new()
            }
        };
        FileAnalysisReport {
            uid: raw.uid,
            name: raw.name,
            file_hash: raw.file_hash,
            file_name: raw.file_name,
            file_extension: raw.file_extension,
            last_analysis_id: raw.last_analysis_id,
            has_been_analysed: raw.has_been_analysed,
            dynamic_analysis: raw.dynamic_analysis,
            static_analysis: raw.static_analysis,
            severity: raw.severity,
            bait_websites: bait_websites_from_raw,
            findings: findings_from_raw,
        }
    }
}