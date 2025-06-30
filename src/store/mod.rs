pub mod sqlite;
pub mod models;
use async_trait::async_trait;
use log::info;
use models::FileAnalysisReport;
use sqlx::{migrate::MigrateDatabase, Sqlite};

const DATABASE_URL: &str = "sqlite:/home/dimeko/dev/malsmug/malsmug.db";

pub trait FileAnalysisReportStoreTraitClone {
    fn clone_box(&self) -> Box<dyn FileAnalysisReportStoreTrait>;
}

impl<T> FileAnalysisReportStoreTraitClone for T
where
    T: 'static + FileAnalysisReportStoreTrait + Clone,
{
    fn clone_box(&self) -> Box<dyn FileAnalysisReportStoreTrait> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn FileAnalysisReportStoreTrait> {
    fn clone(&self) -> Box<dyn FileAnalysisReportStoreTrait> {
        self.clone_box()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("record not found")]
    NotFoundError,
    #[error("generic db error: {0}")]
    GenericError(String),
}

type StoreResult<T> = std::result::Result<T, StoreError>;
#[async_trait]
pub trait FileAnalysisReportStoreTrait: Send + Sync + FileAnalysisReportStoreTraitClone {
    async fn create_file_report(&self, report: FileAnalysisReport) -> StoreResult<FileAnalysisReport>;
    async fn update_file_report(&self, uid: &str, updated_file_analysis_report: FileAnalysisReport) -> StoreResult<FileAnalysisReport>;
    async fn get_file_reports_by_file_hash(&self, hash: &str) -> StoreResult<Vec<FileAnalysisReport>>;
    async fn get_file_report(&self, uid: &str) -> StoreResult<FileAnalysisReport>;
    async fn delete_file_reports_by_hash(&self, hash: &str) -> StoreResult<u64>;
    async fn delete_file_report(&self, uid: &str) -> StoreResult<u64>;
}

#[derive(Clone)]
pub struct DB {
    pub file_analysis_report: Box<dyn FileAnalysisReportStoreTrait>
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Store {
    pub driver: String,
    pub db: DB
}

impl Store {
    pub async fn new(driver: &str) -> Self {
        let store: Store = match driver {
            "sqlite" => {
                if !Sqlite::database_exists(DATABASE_URL).await.unwrap_or(false) {
                    info!("Creating database {}", DATABASE_URL);
                    match Sqlite::create_database(DATABASE_URL).await {
                        Ok(_) => println!("Create db success"),
                        Err(error) => panic!("error: {}", error),
                    }
                } else {
                    info!("Database already exists");
                }
                let pool = sqlx::SqlitePool::connect(DATABASE_URL).await.unwrap();
                Store {
                    driver: "sqlite".to_string(),
                    db: DB {
                        file_analysis_report: Box::new(sqlite::FileAnalysisReportStore::new(pool))
                    }
                }
            },
            _ => {
                panic!("Unsupported database driver: {:?}", driver);
            }
        };
        return store;
    }
}
