
use std::{fs::create_dir_all, os, path::PathBuf, sync::Arc, time::{self}};
use async_std::{stream::StreamExt};
use lapin::options::BasicAckOptions;
use tokio::task;
use axum::{
    extract::{Multipart, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Extension,
    Json,
    Router
};
use uuid::{Uuid};
use rmp_serde::Serializer;
use serde::{Serialize};
use std::thread;
use log::{debug, error, info, warn};
use sha256;
use home;

pub mod rabbitclient;
pub mod types;

use crate::{
    analysis::{
        analyzer::{self, DastAnalyze, Finding, SastAnalyze, Severity},dast::DastAnalyzer, sast::{self}},
    app::types::{EventsFromAnalysis, Response},
    store::{self, models::FileAnalysisReport, StoreError},
    utils
};
use store::Store;

#[derive(Clone)]
struct ApiContext {
    store: Arc<Store>,
    queue: Arc<dyn 'static + Send + rabbitclient::RBMQ>
}

pub trait AppMethods {
    async fn start(&self) -> anyhow::Result<()>;
}

pub struct App {
    bindhost: String,
    store: Store,
    queue: Arc<dyn rabbitclient::RBMQ + Send + Sync>,
    malsmug_dir: PathBuf
}

impl App {
    pub async fn new(h: String, q: Box<dyn rabbitclient::RBMQ + Send + Sync>) -> Self {
        let home_dir = match home::home_dir() {
            Some(path) => {
                path
            },
            _ => panic!("could not determine home dir"),
        };

        let store = Store::new("sqlite").await;
        let app_home_dir = home_dir.join(PathBuf::from("./malsmug"));
        match create_dir_all(&app_home_dir) {
            Ok(_) => (),
            Err(_) => {
                panic!("could not create home dir");
            }
        };
        Self {
            bindhost: h.clone(),
            store,
            queue: Arc::from(q),
            malsmug_dir: app_home_dir
        }
    }
}

fn error_response(e: StoreError) -> (StatusCode, axum::Json<Response>) {
    match &e {
        StoreError::NotFoundError => {
            (StatusCode::NOT_FOUND, Json(
                types::Response{
                        r:  types::Responses::GenericErrorResponse(
                                types::GenericErrorResponse { msg: format!("Entry not found") }
                            )
                        }
                    )
                )
        },
        _ => {
            (StatusCode::BAD_REQUEST, Json(
                types::Response{
                        r:  types::Responses::GenericErrorResponse(
                                types::GenericErrorResponse { msg: format!("Error: {:?}", e.to_string()) }
                            )
                        }
                    )
                )
        }
    }
}

async fn delete_file_reports_by_hash(Extension(ctx): Extension<ApiContext>, Path(file_hash): Path<String>) -> impl IntoResponse {
    let r = match ctx.store.db.file_analysis_report.delete_file_reports_by_hash(&file_hash).await {
        Ok(r) => {
            (StatusCode::OK, Json(
                    types::Response{
                            r:  types::Responses::DeleteFileReport(
                                    types::DeleteFileReport {
                                        file_reports_deleted: r
                                    }
                                )
                            }
                        )
                    )
        },
        Err(e) => error_response(e)
    };
    r
}


async fn delete_file_report(Extension(ctx): Extension<ApiContext>, Path(file_report_uid): Path<String>) -> impl IntoResponse {
    let r = match ctx.store.db.file_analysis_report.delete_file_report(&file_report_uid).await {
        Ok(r) => {
            (StatusCode::OK, Json(
                    types::Response{
                            r:  types::Responses::DeleteFileReport(
                                    types::DeleteFileReport {
                                        file_reports_deleted: r
                                    }
                                )
                            }
                        )
                    )
        },
        Err(e) => error_response(e)
    };
    r
}

async fn get_file_reports(Extension(ctx): Extension<ApiContext>, Path(file_hash): Path<String>) -> impl IntoResponse {
    let r = match ctx.store.db.file_analysis_report.get_file_reports_by_file_hash(file_hash.as_str()).await {
            Ok(r) => {
                debug!("{} file analysis reports found", r.len());
                (StatusCode::OK, Json(
                    types::Response{
                            r:  types::Responses::GetFileReports(
                                    types::GetFileReports {
                                        file_reports: r
                                    }
                                )
                            }
                        )
                    )
            }
            Err(e) => error_response(e)
        };
    r
}

async fn analyse_file(Extension(ctx): Extension<ApiContext>, mut multipart: Multipart) -> impl IntoResponse {
    // let mut total_chunks = 0;
    let mut file_name: String = String::new();
    let mut bait_websites: Vec<String> = Vec::new();
    let mut static_analysis = false;
    let mut dynamic_analysis = false;
    let mut total_file_bytes: Vec<u8> = Vec::new();
    let mut page_for_analysis = String::new();

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
        let field_name = &field.name().unwrap_or_default().to_string();
        match field_name.as_str() {
            "file_for_analysis" => {
                debug!("file name: {}", file_name);
                file_name = field.file_name().unwrap().to_string();
                total_file_bytes = field.bytes().await.unwrap().to_vec();
            },
            "page_for_analysis" => {
                page_for_analysis = field.text().await.unwrap().to_string();
            },
            "bait_websites" => {
                let tmp_bait_websites = field.text().await.unwrap().to_string();
                bait_websites = tmp_bait_websites.split(",").map(|s| s.to_string()).collect();
            },
            "static_analysis" => {
                static_analysis = match field.text().await.unwrap().as_str() {
                    "true" => true,
                    _ => false
                };
            },            
            "dynamic_analysis" => {
                dynamic_analysis = match field.text().await.unwrap().as_str() {
                    "true" => true,
                    _ => false
                };
            },
            _ => {}
        }
    }

    // if user has given a whole page for analysis then we change the below values
    if !page_for_analysis.is_empty() {
        bait_websites = Vec::new();
        bait_websites.push(page_for_analysis.clone());
        let page_name_hash =  sha256::digest( page_for_analysis.clone().as_bytes()).to_string();
        static_analysis = false;
        let tmp_dummy_file_bytes = String::from(
            format!("// dummy file for {} {}", page_for_analysis.clone(), page_name_hash)
        );
        total_file_bytes = tmp_dummy_file_bytes.as_bytes().to_vec();
        file_name = String::from(format!("dummy_{}.js", page_name_hash));
    }

    // let's find the file extension. We need it specifically for othe Static analysis phase
    let file_extension = utils::parse_file_extension_of_file(file_name.clone());
    debug!("file extension of {:?}: {:?}", file_name.as_str(), file_extension);

    // calculation of the hash of the file content
    let file_hash_from_bytes = sha256::digest(&total_file_bytes).to_string();
    let analysis_uuid = Uuid::new_v4();

    // save report reference to database
    let file_analysis_report  = match ctx.store.db.file_analysis_report.create_file_report(FileAnalysisReport::new(
        file_name.clone(),
        file_hash_from_bytes.clone(),
        file_name.clone(),
        file_extension,
        analysis_uuid.to_string(),
        false,
        dynamic_analysis,static_analysis,
        0, bait_websites.to_owned(), Vec::new())).await {
            Ok(f) => {
                info!("file {:?} report saved", file_name.clone());
                f
            },
            Err(e) => {
                error!("file {:?} report was NOT saved. Error: {:?}", file_name.clone(), e);
                return (StatusCode::BAD_REQUEST, Json(types::Response{
                    r:  types::Responses::GenericErrorResponse (
                            types::GenericErrorResponse { msg: "File was not saved".to_string() }
                        )
                }))
            }
        };

    if dynamic_analysis {
        // prepare the FileForAnalysis details to be sent as byte stream to RBMQ
        let file_for_analysis = types::FileForAnalysis {
            file_name: file_name.clone(),
            file_hash: file_hash_from_bytes.clone(),
            analysis_id: analysis_uuid.to_string(),
            bait_websites: bait_websites,
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

        info!("file {:?} sent to queue for analysis", file_name);
    }

    if static_analysis {
        let mut static_analyser = sast::SastAnalyzer::new();
        match ctx.store.db.file_analysis_report.get_file_report(file_analysis_report.uid.clone().unwrap().as_str()).await {
            Ok(mut r) => {
                match static_analyser.analyze(r.to_owned(), total_file_bytes) {
                    Ok(mut f) => {
                        info!("found {} findings for {:?}", f.len(), r.clone().file_name);
                        // r.has_started_analysis = true; TODO: set a separate column to check if is analysed dynamically has_started_analysis_dynamically
                        let mut tmp_findings: Vec<Finding> = Vec::new();

                        let mut max_severity = Severity::Low;
                        for f in f.clone() {
                            info!("finding: {:?}, {}", f.title, f.severity);
                            if f.severity > max_severity {
                                max_severity = f.severity;
                            }
                        }

                        for rf in r.clone().findings {
                            if rf.r#type != analyzer::AnalysisType::Static {
                                tmp_findings.push(rf.to_owned());
                                if rf.severity > max_severity {
                                    max_severity = rf.severity;
                                }
                            }
                        }

                        let file_report_uid = r.clone().uid.unwrap();

                        r.severity = max_severity as i64;
                        r.findings = tmp_findings;
                        r.findings.append(&mut f);
                        match ctx.store.db.file_analysis_report.update_file_report(
                            file_report_uid.as_str(), 
                            r).await {
                                Ok(r) => {
                                    debug!("file report was updated successfully: {:?}", r);
                                },
                                Err(e) => {
                                    error!(
                                        "[static-analysis] could not update analysed file db record: {:?}. Error: {:?}",
                                        file_report_uid, e);
                                }
                            }
                    },
                    Err(e) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(types::Response{
                            r:  types::Responses::GenericErrorResponse (
                                    types::GenericErrorResponse { msg: format!("Error occured with static analyser: {:?}", e) }
                                )
                        } ))
                    }
                };
            },
            Err(e) => {
                match &e {
                    StoreError::NotFoundError => {
                        return (StatusCode::NOT_FOUND, Json(
                            types::Response{
                                    r:  types::Responses::GenericErrorResponse(
                                            types::GenericErrorResponse { msg: format!("Entries not found") }
                                        )
                                    }
                                )
                            )
                    },
                    _ => {
                        return (StatusCode::BAD_REQUEST, Json(types::Response{
                            r:  types::Responses::GenericErrorResponse (
                                    types::GenericErrorResponse { msg: format!("Could not find newlly created file report entry.") }
                                )
                        } ))
                    }
                }
            }
        }
    }
   
    (StatusCode::CREATED, Json(
        types::Response{
                r:  types::Responses::FileUploadResponse(
                        types::FileUploadResponse {
                            msg: "file was submitted".to_string(),
                            file_hash: file_hash_from_bytes,
                            file_analysis_report_uid: file_analysis_report.uid.unwrap()
                        }
                    )
                }
            )
    )
}

impl AppMethods for App {
    // async 
    async fn start(&self) -> anyhow::Result<()> {
        let inner_queue = self.queue.clone();
        let inner_store = self.store.clone();
        let inner_malsmug_dir = self.malsmug_dir.clone();

        let app = Router::new()
            .route("/analyse-file", post(analyse_file))
            .route("/delete-file-report/{file_report_uid}", delete(delete_file_report))
            .route("/delete-file-reports/{file_hash}", delete(delete_file_reports_by_hash))
            .route("/get-file-reports/{file_hash}", get(get_file_reports))
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
                            // initialize the dynamic analyzer ready to process incoming events
                            let mut dynamic_analyser = DastAnalyzer::new(inner_malsmug_dir);

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
                                        let file_reports_with_the_same_hash = match inner_store.db
                                            .file_analysis_report
                                            .get_file_reports_by_file_hash(events_for_analysis.file_hash.as_str()).await {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    match &e {
                                                        StoreError::NotFoundError => {
                                                            error!("report does not exist in database, aborting");
                                                            continue;
                                                        }
                                                        _ => {
                                                            error!("generic db error: {:?}", e);
                                                        }
                                                    };
                                                    continue;
                                                }
                                            };
                                        // let's find the file_analysis_report that is related to the specific iocs
                                        let mut file_report: FileAnalysisReport = FileAnalysisReport::empty();
                                        for far in file_reports_with_the_same_hash {
                                            if far.last_analysis_id == events_for_analysis.analysis_id {
                                                file_report = far;
                                                break;
                                            }
                                        }

                                        // this is used to decide whether we must to append to existing findings or
                                        // to initialize the dynamic analysis findings from the start.
                                        // If the previous retreived findings have the same analysis_id, means that
                                        // we still are on the same context of analysis session so we must keep appending.
                                        // If they are different we must initialize them from the start as it mean we are
                                        // on a different analysis session. 
                                        let mut append_to_findings = false;
                                        if file_report.has_started_analysis {
                                            append_to_findings = true;
                                        }
                                        file_report.has_started_analysis = true; // have to rename has_started_analysis
                                        if file_report.dynamic_analysis {
                                            match dynamic_analyser.analyze(file_report.clone(), events_for_analysis.iocs).await {
                                                Ok(mut f) => {
                                                    info!("found {} findings for {:?}", f.len(), file_report.file_name);
                                                    let mut tmp_findings: Vec<Finding> = Vec::new();
                                                    let mut max_severity = Severity::Low;
                                                    for f in f.clone() {
                                                        info!("finding: {:?}, {}", f.title, f.severity);
                                                        if f.severity > max_severity {
                                                            max_severity = f.severity;
                                                        }
                                                    }

                                                    for rf in file_report.findings {
                                                        if rf.r#type != analyzer::AnalysisType::Dynamic || append_to_findings {
                                                            tmp_findings.push(rf.to_owned());
                                                            if rf.severity > max_severity {
                                                                max_severity = rf.severity;
                                                            }
                                                        }
                                                    }

                                                    let file_report_uid = file_report.uid.clone().unwrap();

                                                    file_report.severity = max_severity as i64;
                                                    file_report.findings = tmp_findings;
                                                    file_report.findings.append(&mut f);
                                                    match inner_store.db.file_analysis_report.update_file_report(
                                                        file_report_uid.as_str(), 
                                                        file_report).await {
                                                            Ok(r) => {
                                                                debug!("file report was updated successfully: {:?}", r);
                                                            },
                                                            Err(e) => {
                                                                error!(
                                                                    "[dynamic-analysis] could not update analysed file db record: {:?}. Error: {:?}",
                                                                    file_report_uid, e);
                                                            }
                                                        }
                                                },
                                                Err(e) => {
                                                    error!("error occured analysing file {:?}, Error: {:?}", file_report.file_name, e);
                                                    continue;
                                                }
                                            };
                                        }
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
        let listener = tokio::net::TcpListener::bind(&self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
