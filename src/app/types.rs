use rmp;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

use crate::analysis::dast_event_types;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct FileForAnalysis {
    pub file_name: String,
    pub file_hash: String,
    pub file_bytes: Vec<u8>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventsFromAnalysis {
    pub file_name: String,
    pub file_hash: String,
    pub events: Vec<dast_event_types::Event>
}

// HTTP types
#[derive(Deserialize, Serialize)]
pub struct Response {
    pub msg: String,
}