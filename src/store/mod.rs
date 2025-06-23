pub mod sqlite;
pub mod models;
use async_trait::async_trait;
use log::info;
use models::FileAnalysisReport;
use sqlite::FileAnalysisReportStore;
use sqlx::{migrate::MigrateDatabase, Error, Sqlite};

const DATABASE_URL: &str = "sqlite:/home/dimeko/dev/malsmug/malsmug.db";
#[async_trait]
pub trait FileAnalysisReportStoreTrait: Send + Sync {
    async fn create_file_report(&self, report: FileAnalysisReport) -> anyhow::Result<()>;
    async fn get_file_report(&self, uid: &str) -> Option<FileAnalysisReport>;
}

struct Models {
    file_analysis_report: FileAnalysisReportStore
}

pub struct Store {
    driver: String,
    models: Models
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
                    models: Models {
                        file_analysis_report: FileAnalysisReportStore::new(pool)
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