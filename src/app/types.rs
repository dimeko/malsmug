use serde::{Deserialize, Serialize};
use crate::{analysis::dast_ioc_types::{self}, store::models::FileAnalysisReport};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct FileForAnalysis {
    pub file_name: String,
    pub file_hash: String,
    pub analysis_id: String,
    pub bait_websites: Vec<String>,
    pub file_bytes: Vec<u8>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventsFromAnalysis {
    pub file_hash: String,
    pub analysis_id: String,
    pub iocs: Vec<dast_ioc_types::IoC>
}

// HTTP types
#[derive(Deserialize, Serialize)]
pub struct GenericSuccessResponse {
    pub msg: String,
}

#[derive(Deserialize, Serialize)]
pub struct GenericErrorResponse {
    pub msg: String,
}

#[derive(Deserialize, Serialize)]
pub struct FileUploadResponse {
    pub msg: String,
    pub file_hash: String,
    pub file_analysis_report_uid: String
}

#[derive(Deserialize, Serialize)]
pub struct GetFileReport {
    pub file_report: FileAnalysisReport,
}

#[derive(Deserialize, Serialize)]
pub struct GetFileReports {
    pub file_reports: Vec<FileAnalysisReport>,
}

#[derive(Deserialize, Serialize)]
pub struct DeleteFileReport {
    pub file_reports_deleted: u64,
}

#[derive(Deserialize, Serialize)]
pub enum Responses {
    #[serde(rename = "body")]
    GenericErrorResponse(GenericErrorResponse),
    #[serde(rename = "body")]
    GenericSuccessResponse(GenericSuccessResponse),
    #[serde(rename = "body")]
    FileUploadResponse(FileUploadResponse),
    #[serde(rename = "body")]
    GetFileReport(GetFileReport),
    #[serde(rename = "body")]
    GetFileReports(GetFileReports),
    #[serde(rename = "body")]
    DeleteFileReport(DeleteFileReport)
}

#[derive(Deserialize, Serialize)]
pub struct Response {
    pub r: Responses,
}
