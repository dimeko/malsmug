#[derive(Clone, Debug)]
pub struct FileAnalysisReport {
    pub uid: Option<String>,
    pub name: String,
    pub file_hash: String,
    pub file_name: String,
    pub has_been_analysed: bool,
    pub severity: i64,
    pub analysis_report_description: String,
}

impl FileAnalysisReport {
    pub fn new(
        name: String,
        file_hash: String,
        file_name: String,
        has_been_analysed: bool,
        severity: i64, analysis_report_description: String) -> Self {
          FileAnalysisReport {
            name,
            file_hash,
            file_name,
            has_been_analysed,
            severity,
            analysis_report_description,
            uid: None
          }  
    }
}