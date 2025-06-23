
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

// #[async_trait]
impl FileAnalysisReportStoreTrait for FileAnalysisReportStore {
    async fn get_file_report(&self, uid: &str) -> Result<(), Error> {
        let reports = sqlx::query_as!(
            FileAnalysisReport, r#"SELECT uid,
                name,
                file_hash,
                file_name,
                analysis_report_description
                FROM file_analysis_reports WHERE uid = ?"#, uid)
            .fetch_optional(&self.pool)
            .await?;
            Ok(())
    }

    async fn create_file_report(&self, mut report: FileAnalysisReport) -> Result<(), Error> {
        let new_uuid = Uuid::new_v4();
        report.uid = new_uuid.to_string(); // TODO: generate uuid
    
        sqlx::query!(r#"INSERT INTO file_analysis_reports
                (uid, name, file_hash, file_name, analysis_report_description)
                VALUES (?,?,?,?,?)"#,
            report.uid,
            report.name,
            report.file_hash,
            report.file_name,
            report.analysis_report_description
        ).execute(&self.pool).await?;
        Ok(())
    }
}
