
use crate::{analysis::analyzer::Finding, store::StoreResult, store::StoreError};

use super::{models::FileAnalysisReport, FileAnalysisReportStoreTrait};
use log::debug;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use uuid::{Uuid};
use async_trait::async_trait;

#[derive(Clone)]
pub struct FileAnalysisReportStore {
    pool: Pool<Sqlite>,
}

impl FileAnalysisReportStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct FileAnalysisReportRaw {
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
    pub bait_websites: String,
    pub findings: String,
}

// impl From<FileAnalysisReport> for FileAnalysisReportRaw {
//   fn from(file_analysis_report: FileAnalysisReport) -> Self {
//         FileAnalysisReportRaw {
//             uid: file_analysis_report.uid,
//             name: file_analysis_report.name,
//             file_hash: file_analysis_report.file_hash,
//             file_name: file_analysis_report.file_name,
//             file_extension: file_analysis_report.file_extension,
//             has_been_analysed: file_analysis_report.has_been_analysed,
//             dynamic_analysis: file_analysis_report.dynamic_analysis,
//             static_analysis: file_analysis_report.static_analysis,
//             severity: file_analysis_report.severity,
//             bait_websites: file_analysis_report.bait_websites.join(","),
//             analysis_report: file_analysis_report.analysis_report,
//         }
//     }
// }

#[async_trait]
impl FileAnalysisReportStoreTrait for FileAnalysisReportStore {
    async fn get_file_report(&self, uid: &str) -> StoreResult<FileAnalysisReport> {
        let report_raw = sqlx::query_as!(
            FileAnalysisReportRaw, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                file_extension,
                last_analysis_id,
                has_been_analysed,
                dynamic_analysis,
                static_analysis,
                severity,
                bait_websites,
                findings
                FROM file_analysis_reports WHERE uid = ?"#, uid)
            .fetch_one(&self.pool)
            .await;
        match report_raw {
            Ok(r) =>
                return Ok(FileAnalysisReport::from(r)),
            Err(e) => {
                match &e {
                    sqlx::error::Error::RowNotFound => {
                        return Err(StoreError::NotFoundError)
                    },
                    _ => {
                        return Err(StoreError::GenericError(e.to_string()))
                    }
                }
            }
        }
        
    }

    async fn get_file_reports_by_file_hash(&self, hash: &str) -> StoreResult<Vec<FileAnalysisReport>> {
        let reports_raw = sqlx::query_as!(
            FileAnalysisReportRaw, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                file_extension,
                last_analysis_id,
                has_been_analysed,
                dynamic_analysis,
                static_analysis,
                severity,
                bait_websites,
                findings
                FROM file_analysis_reports WHERE file_hash = ?"#, hash)
            .fetch_all(&self.pool)
            .await;
        match reports_raw {
            Ok(rws) => {
                let mut reports: Vec<FileAnalysisReport> = Vec::new();
                for rw in rws {
                    reports.push(FileAnalysisReport::from(rw));
                }
                return Ok(reports);
            },
            Err(e) => {
                match &e {
                    sqlx::error::Error::RowNotFound => {
                        return Err(StoreError::NotFoundError)
                    },
                    _ => {
                        return Err(StoreError::GenericError(e.to_string()))
                    }
                }
            }
        }

        
    }

    async fn update_file_report(&self, uid: &str, updated_file_analysis_report: FileAnalysisReport) -> StoreResult<FileAnalysisReport> {
        let json_string_findings = match serde_json::to_string::<Vec<Finding>>(&updated_file_analysis_report.findings) {
            Ok(r) => r,
            Err(_) => {
                debug!("ERROR: could convert findings json  to json string");
                String::new()
            }
        };
        let result = sqlx::query!(r#"UPDATE file_analysis_reports
                    SET has_been_analysed = ?, severity = ?, findings = ?, last_analysis_id = ? WHERE uid = ? 
                "#,
                updated_file_analysis_report.has_been_analysed,
                updated_file_analysis_report.severity,
                json_string_findings,
                updated_file_analysis_report.last_analysis_id,
                uid
            )
            .fetch_one(&self.pool)
            .await;
        return match result {
            Ok(_) => {
                Ok(updated_file_analysis_report)
            },
            Err(e) => {
                match &e {
                    sqlx::error::Error::RowNotFound => {
                        Err(StoreError::NotFoundError)
                    },
                    _ => {
                        Err(StoreError::GenericError(e.to_string()))
                    }
                }
            }
        }
    }

    async fn delete_file_report(&self, uid: &str) -> StoreResult<u64> {
        let res = sqlx::query!(r#"DELETE FROM file_analysis_reports WHERE uid = ? "#, uid).execute(&self.pool)
            .await;
        return match res {
            Ok(r) => {
                Ok(r.rows_affected())
            },
            Err(e) => {
                match &e {
                    sqlx::error::Error::RowNotFound => {
                        Err(StoreError::NotFoundError)
                    },
                    _ => {
                        Err(StoreError::GenericError(e.to_string()))
                    }
                }
            }
        }
    }

    async fn delete_file_reports_by_hash(&self, file_hash: &str) -> StoreResult<u64> {
        let res = sqlx::query!(r#"DELETE FROM file_analysis_reports WHERE file_hash = ? "#, file_hash).execute(&self.pool)
            .await;
        return match res {
            Ok(r) => {
                Ok(r.rows_affected())
            },
            Err(e) => {
                match &e {
                    sqlx::error::Error::RowNotFound => {
                        Err(StoreError::NotFoundError)
                    },
                    _ => {
                        Err(StoreError::GenericError(e.to_string()))
                    }
                }
            }
        }
    }


    async fn create_file_report(&self, mut report: FileAnalysisReport) -> StoreResult<FileAnalysisReport> {
        let new_uuid = Uuid::new_v4();
        report.uid = Some(new_uuid.to_string()); // TODO: generate uuid
        let comma_sep_bait_websites = report.bait_websites.join(",");
        let json_string_findings = match serde_json::to_string::<Vec<Finding>>(&report.findings) {
            Ok(r) => r,
            Err(_) => {
                debug!("ERROR: could convert findings json  to json string");
                String::new()
            }
        };

        let res = sqlx::query!(r#"INSERT INTO file_analysis_reports
                (
                    uid,
                    name,
                    file_hash,
                    file_name,
                    file_extension,
                    last_analysis_id,
                    has_been_analysed,
                    dynamic_analysis,
                    static_analysis,
                    severity,
                    bait_websites,
                    findings)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"#,
            report.uid,
            report.name,
            report.file_hash,
            report.file_name,
            report.file_extension,
            report.last_analysis_id,
            report.has_been_analysed,
            report.dynamic_analysis,
            report.static_analysis,
            report.severity,
            comma_sep_bait_websites,
            json_string_findings
        ).execute(&self.pool).await;
        match res {
            Ok(_) => {
                return Ok(report)
            },
            Err(e) => {
                Err(StoreError::GenericError(e.to_string()))
            }
        }
    }
}
