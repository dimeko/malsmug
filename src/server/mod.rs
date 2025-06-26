
use std::{sync::Arc, time::{self}};
use tokio::task;
use axum::{
    extract::Multipart,
    http::StatusCode,
    response::IntoResponse,
    routing::{post},
    Extension,
    Json,
    Router
};
use std::thread;
use log::{debug, info};

use serde::{Deserialize, Serialize};

pub mod rabbitclient;

use crate::{store};
use store::Store;

#[derive(Clone)]
struct ApiContext {
    queue: Arc<dyn 'static + Send + rabbitclient::Queue>
}

#[derive(Deserialize, Serialize)]
struct Response {
    msg: String,
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

async fn upload_file(Extension(ctx): Extension<ApiContext>, mut multipart: Multipart) -> impl IntoResponse {
    // let mut total_chunks = 0;
    let mut file_name: String = String::new();
    let mut total_file_bytes: Vec<u8> = Vec::new();
    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(Response { msg: format!("Error reading multipart field: {:?}", err) }))
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

    let _ = ctx.queue.publish(
        ctx.queue.get_core_files_queue(),
        ctx.queue.get_main_exchange(),
        total_file_bytes).await;

    info!("file {:?} sent to queue", file_name);
    (StatusCode::CREATED, Json(Response { msg: "file was submitted".to_string()}))
}

impl<'a> ServerMethods<'a> for Server<'a> {
    // async 
    async fn start(&self) -> anyhow::Result<()> {
        let inner_queue = self.queue.clone();
        let app = Router::new()
            .route("/upload_file", post(upload_file))
            .route_layer(
                Extension(ApiContext {
                    queue: inner_queue.clone(),
                })
            );

        let _ = task::spawn(async move {
            // loop {
                info!("polling results");
                inner_queue.consume(
                    inner_queue.get_sandbox_iocs_queue(),
                    |data: Vec<u8>| {
                        info!("data: {:?}", data[0]);
                    }).await;
                // info!("analysis results: {:?}", res);
                // consumer.
                thread::sleep(time::Duration::from_secs(1));
            // }
        });

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
