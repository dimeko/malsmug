
use super::{models::FileAnalysisReportStore, FileAnalysisReportStoreStore};
use async_trait::async_trait;
use sqlx::SqlitePool;
use uuid::{self, Uuid};
pub struct SqliteFileAnalysisReport {
    pool: SqlitePool,
}

impl SqliteFileAnalysisReport {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FileAnalysisReportStore for SqliteFileAnalysisReport {
    async fn get_file_report(&self, uid: &str) -> Option<FileAnalysisReport> {
        sqlx::query_as!(FileAnalysisReport, "SELECT
            uid,
            name,
            file_hash,
            file_name,
            analysis_report_description, FROM file_analysis_reports WHERE uid = ?", uid)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
    }

    async fn create_file_report(&self, report: FileAnalysisReport) -> Option<User> {
        let new_uuid = Uuid::new_v6();
        report.uid = new_uuid; // TODO: generate uuid
        sqlx::query!("INSERT INTO file_analysis_reports" \
                "(uid, name, file_hash, file_name, analysis_report_description" \
                "VALUES (?,?,?,?,?)",
            report.uid,
            report.name,
            report.file_hash,
            report.file_name,
            report.analysis_report_description
        ).execute(&self.pool).await?;
        Ok(())
    }
}
