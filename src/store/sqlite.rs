
use super::{models::FileAnalysisReport, FileAnalysisReportStoreTrait};
use sqlx::{Pool, Sqlite, Error};
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

#[async_trait]
impl FileAnalysisReportStoreTrait for FileAnalysisReportStore {
    async fn get_file_report(&self, uid: &str) -> Option<FileAnalysisReport> {
        let report = sqlx::query_as!(
            FileAnalysisReport, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                file_extension,
                has_been_analysed,
                severity,
                analysis_report
                FROM file_analysis_reports WHERE uid = ?"#, uid)
            .fetch_one(&self.pool)
            .await.ok();
            report
    }

    async fn get_file_report_by_file_hash(&self, hash: &str) -> Option<FileAnalysisReport> {
        let report = sqlx::query_as!(
            FileAnalysisReport, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                file_extension,
                has_been_analysed,
                severity,
                analysis_report
                FROM file_analysis_reports WHERE file_hash = ?"#, hash)
            .fetch_one(&self.pool)
            .await.ok();
            report 
    }

    async fn update_file_report(&self, uid: &str, updated_file_analysis_report: FileAnalysisReport) -> anyhow::Result<()> {
        sqlx::query!(r#"UPDATE file_analysis_reports
                    SET has_been_analysed = ?, severity = ?, analysis_report = ? WHERE uid = ? 
                "#,
                updated_file_analysis_report.has_been_analysed,
                updated_file_analysis_report.severity,
                updated_file_analysis_report.analysis_report,
                uid
            )
            .fetch_one(&self.pool)
            .await.ok();
        Ok(())
    }

    async fn create_file_report(&self, mut report: FileAnalysisReport) -> anyhow::Result<()> {
        let new_uuid = Uuid::new_v4();
        report.uid = Some(new_uuid.to_string()); // TODO: generate uuid
    
        sqlx::query!(r#"INSERT INTO file_analysis_reports
                (uid, name, file_hash, file_name, file_extension, has_been_analysed, severity, analysis_report)
                VALUES (?,?,?,?,?,?,?,?)"#,
            report.uid,
            report.name,
            report.file_hash,
            report.file_name,
            report.file_extension,
            report.has_been_analysed,
            report.severity,
            report.analysis_report
        ).execute(&self.pool).await?;
        Ok(())
    }
}
