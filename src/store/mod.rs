pub mod sqlite;
pub mod models;

use models::FileAnalysisReport;

#[async_trait::async_trait]
pub trait FileAnalysisReportStore {
    async fn create_file_report(&self, report: FileAnalysisReport) -> Option<FileAnalysisReport>;
    async fn get_file_report(&self, uid: &str) -> anyhow::Result<()>;
}

struct Models {
    file_analysis_report: FileAnalysisReport
}

pub struct Store {
    driver: String,
    models: Models
}

impl Store {
    async fn new(driver: &str) -> Self {
        let store: Store = match driver.as_str() {
            "sqlite" => {
                let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
                SqliteUserStore::new(pool)
            },
            _ => {
                panic!("Unsupported database driver: {:?}", driver);
            }
        };
        return store;
    }
}