
use std::{sync::Arc, time::{self}};
use async_std::stream::StreamExt;
use lapin::options::BasicAckOptions;
use tokio::task;
use axum::{
    extract::{Multipart, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{post, get},
    Extension,
    Json,
    Router
};
use rmp_serde::Serializer;
use serde::{Serialize};
use std::thread;
use log::{debug, error, info, warn};
use sha256;

pub mod rabbitclient;
pub mod types;

use crate::{
    analysis::{
        analyzer::{DastAnalyze, Severity},dast::DastAnalyzer},
    app::types::EventsFromAnalysis,
    store::{self, models::FileAnalysisReport},
    utils
};
use store::Store;

#[derive(Clone)]
struct ApiContext {
    store: Arc<Store>,
    queue: Arc<dyn 'static + Send + rabbitclient::Queue>
}

pub trait ServerMethods<'a> {
    // async fn upload_file(self, multipart: Multipart) -> (StatusCode, Json<Response<'a>>) ;
    async fn start(&self) -> anyhow::Result<()>;
}

pub struct Server<'a> {
    bindhost: &'a str,
    store: Store,
    queue: Arc<dyn rabbitclient::Queue + Send + Sync> // rabbitclient::Queue is supposed to move to a more abstract queue mod
}

impl<'a> Server<'a> {
    pub async fn new(h: &'a str, q: Box<dyn rabbitclient::Queue + Send + Sync>) -> Self {
        let store = Store::new("sqlite").await;
        Self {
            bindhost: h,
            store,
            queue: Arc::from(q)
        }
    }
}

async fn get_file_report(Extension(ctx): Extension<ApiContext>, Path(file_hash): Path<String>) -> impl IntoResponse {
    let r = match ctx.store.db.file_analysis_report.get_file_report_by_file_hash(file_hash.as_str()).await {
            Some(r) => {
                (StatusCode::CREATED, Json(
                    types::Response{
                            r:  types::Responses::GetFileReport(
                                    types::GetFileReport {
                                        file: r.copy_no_uid() // avoid returning uid. Just because we can
                                    }
                                )
                            }
                        )
                    )
            }
            None => {
                (StatusCode::NOT_FOUND, Json(types::Response{
                    r:  types::Responses::GenericErrorResponse (
                            types::GenericErrorResponse { msg: format!("Error getting file report. File hash does not exist") }
                        )
                } ))
            }
        };
    r
}

async fn upload_file(Extension(ctx): Extension<ApiContext>, mut multipart: Multipart) -> impl IntoResponse {
    // let mut total_chunks = 0;
    let mut file_name: String = String::new();
    let mut total_file_bytes: Vec<u8> = Vec::new();
    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(types::Response{
                r:  types::Responses::GenericErrorResponse (
                        types::GenericErrorResponse { msg: format!("Error reading multipart field: {:?}", err) }
                    )
            } ))
        }
    } {
        let field_name = field.name().unwrap_or_default().to_string();
        match field_name.as_str() {
            "fileName" => {
                file_name = field.name().unwrap().to_string(); 
                debug!("file name: {}", file_name);
                total_file_bytes = field.bytes().await.unwrap().to_vec();
            },
            _ => {}
        }
    }

    // let's find the file extension. We need it specifically for othe Static analysis phase
    let file_extension = utils::parse_file_extension_of_file(file_name.clone());

    // calculation of the hash of the file content
    let file_hash_from_bytes = sha256::digest(&total_file_bytes).to_string();

    // save report reference to database
    match ctx.store.db.file_analysis_report.create_file_report(FileAnalysisReport::new(
        file_name.clone(),
        file_hash_from_bytes.clone(),
        file_name.clone(),
        file_extension,
        false,
        0, "".to_string())).await {
            Ok(_) => {
                info!("file {:?} report saved", file_name.clone());
            },
            Err(e) => {
                error!("file {:?} report was NOT saved. Error: {:?}", file_name.clone(), e);
                return (StatusCode::BAD_REQUEST, Json(types::Response{
                    r:  types::Responses::GenericErrorResponse (
                            types::GenericErrorResponse { msg: "File was not saved".to_string() }
                        )
                }))
            }
        }

    // prepate the FileForAnalysis details to be sent as byte stream to RBMQ
    let file_for_analysis = types::FileForAnalysis {
        file_name: file_name.clone(),
        file_hash: file_hash_from_bytes.clone(),
        file_bytes: total_file_bytes.clone()
    };

    let mut file_for_analysis_buf: Vec<u8> = Vec::new();

    // Serialize the FileForAnalysis to byte Vec
    file_for_analysis.serialize(&mut Serializer::new(&mut file_for_analysis_buf)).unwrap();

    // pulish the data
    let _ = ctx.queue.publish(
        ctx.queue.get_core_files_queue(),
        ctx.queue.get_main_exchange(),
        file_for_analysis_buf).await;

    info!("file {:?} sent to queue", file_name);
    (StatusCode::CREATED, Json(
        types::Response{
                r:  types::Responses::FileUploadResponse(
                        types::FileUploadResponse {
                            msg: "file was submitted".to_string(),
                            file_hash: file_hash_from_bytes
                        }
                    )
                }
            )
    )
}

impl<'a> ServerMethods<'a> for Server<'a> {
    // async 
    async fn start(&self) -> anyhow::Result<()> {
        let inner_queue = self.queue.clone();
        let inner_store = self.store.clone();
        let app = Router::new()
            .route("/upload-file", post(upload_file))
            .route("/get-file-report/{file_hash}", get(get_file_report))
            .route_layer(
                Extension(ApiContext {
                    store: Arc::from(self.store.clone()),
                    queue: inner_queue.clone(),
                })
            );

        let _ = task::spawn(async move {
                match inner_queue.consume(
                    inner_queue.get_sandbox_iocs_queue()).await {
                        Ok(mut c) => {
                            let mut dynamic_analyser = DastAnalyzer::new();
                            while let Some(delivery) = c.next().await {
                                match delivery {
                                    Ok(d) => {
                                        debug!("data arrived from: {:?}", d.exchange);
                                        let ack_args = BasicAckOptions {
                                            multiple: false
                                        };
                                        let _ = d.ack(ack_args).await;

                                        // from bytes to string (json string)
                                        let data_string = match str::from_utf8(&d.data) {
                                            Ok(r) => {
                                                debug!("data parsed: {:?}", &r);
                                                r
                                            },
                                            Err(e) => {
                                                error!("could not parse data from queue: {:?}", e);
                                                continue;
                                            }
                                        };

                                        // from json string to struct
                                        let events_for_analysis: EventsFromAnalysis = match serde_json::from_str(data_string) {
                                            Ok(r) => r,
                                            Err(e) => {
                                                error!("could not parse json string from queue: {:?}", e);
                                                continue;
                                            }
                                        };

                                        // get file report stored in database on file upload
                                        let mut file_report = match inner_store.db
                                            .file_analysis_report
                                            .get_file_report_by_file_hash(events_for_analysis.file_hash.as_str()).await {
                                                Some(r) => r,
                                                None => {
                                                    error!("report does not exist in database, aborting");
                                                    continue;
                                                }
                                            };

                                        // analyze!
                                        match dynamic_analyser.analyze(file_report.clone(), events_for_analysis.events) {
                                            Ok(r) => {
                                                info!("found {} findings", r.len());
                                                file_report.has_been_analysed = true;
                                                let mut max_severity = Severity::Low;
                                                for f in r.clone() {
                                                    info!("finding: {:?}, {}", f.title, f.severity);
                                                    if f.severity > max_severity {
                                                        max_severity = f.severity;
                                                    }
                                                }
                                                let file_report_uid = file_report.uid.clone().unwrap();

                                                file_report.severity = max_severity as i64;
                                                file_report.analysis_report = serde_json::to_string(&r).unwrap();
                                                match inner_store.db.file_analysis_report.update_file_report(
                                                    file_report_uid.as_str(), 
                                                    file_report).await {
                                                        Ok(r) => {
                                                            debug!("file report was updated successfully: {:?}", r);
                                                        },
                                                        Err(e) => {
                                                            error!(
                                                                "could not update analysed file db record: {:?}. Error: {:?}",
                                                                file_report_uid, e);
                                                        }
                                                    }
                                            },
                                            Err(e) => {
                                                error!("error occured analysing file {:?}, Error: {:?}", file_report.file_name, e);
                                                continue;
                                            }
                                        };

                                    },
                                    Err(e) => {
                                        error!("could not get data: {:?}", e);
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            error!("could not create consumer: {:?}", e);
                        }
                    };
                warn!("reached the end of the stream. Probably we should never reach here.");
                thread::sleep(time::Duration::from_secs(1));
            });

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
