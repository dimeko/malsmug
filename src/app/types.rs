use rmp;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

use crate::{analysis::dast_event_types::{self, Event}, store::models::FileAnalysisReport};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct FileForAnalysis {
    pub file_name: String,
    pub file_hash: String,
    pub file_bytes: Vec<u8>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventsFromAnalysis {
    pub file_hash: String,
    pub events: Vec<dast_event_types::Event>
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
    pub file_hash: String
}

#[derive(Deserialize, Serialize)]
pub struct GetFileReport {
    pub file: FileAnalysisReport,
}

#[derive(Deserialize, Serialize)]
pub enum Responses {
    GenericErrorResponse(GenericErrorResponse),
    GenericSuccessResponse(GenericSuccessResponse),
    FileUploadResponse(FileUploadResponse),
    GetFileReport(GetFileReport)
}

#[derive(Deserialize, Serialize)]
pub struct Response {
    pub r: Responses,
}
