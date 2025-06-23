#[derive(Clone, Debug)]
pub struct FileAnalysisReport {
    pub uid: String,
    pub name: String,
    pub file_hash: String,
    pub file_name: String,
    pub has_been_analysed: bool,
    pub severity: i64,
    pub analysis_report_description: String,
}