use rmp;
use serde::{Deserialize, Serialize};
use rmp_serde::{Deserializer, Serializer};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct FileForAnalysis {
    pub file_name: String,
    pub file_hash: String,
    pub file_bytes: Vec<u8>
}

// HTTP types
#[derive(Deserialize, Serialize)]
pub struct Response {
    pub msg: String,
}