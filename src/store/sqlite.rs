
use super::{models::FileAnalysisReport, FileAnalysisReportStoreTrait};
use sqlx::{Pool, Sqlite, Error};
use uuid::{Uuid};
use async_trait::async_trait;
pub struct FileAnalysisReportStore {
    pool: Pool<Sqlite>,
}

impl FileAnalysisReportStore {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FileAnalysisReportStoreTrait for FileAnalysisReportStore {
    async fn get_file_report(&self, uid: &str) -> Option<FileAnalysisReport> {
        let report = sqlx::query_as!(
            FileAnalysisReport, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                has_been_analysed,
                severity,
                analysis_report_description
                FROM file_analysis_reports WHERE uid = ?"#, uid)
            .fetch_one(&self.pool)
            .await.ok();
            report 
    }

    async fn create_file_report(&self, mut report: FileAnalysisReport) -> anyhow::Result<()> {
        let new_uuid = Uuid::new_v4();
        report.uid = new_uuid.to_string(); // TODO: generate uuid
    
        sqlx::query!(r#"INSERT INTO file_analysis_reports
                (uid, name, file_hash, file_name, has_been_analysed, severity, analysis_report_description)
                VALUES (?,?,?,?,?,?,?)"#,
            report.uid,
            report.name,
            report.file_hash,
            report.file_name,
            report.has_been_analysed,
            report.severity,
            report.analysis_report_description
        ).execute(&self.pool).await?;
        Ok(())
    }
}
