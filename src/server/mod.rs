
use std::fmt::format;

use axum::{
    extract::Multipart, http::StatusCode, middleware::AddExtension, response::IntoResponse, routing::{get, post}, Extension, Json, Router
};
use amqprs::{
    callbacks::{DefaultChannelCallback, DefaultConnectionCallback}, channel::{BasicConsumeArguments, BasicPublishArguments, Channel, QueueBindArguments, QueueDeclareArguments}, connection::{Connection, OpenConnectionArguments}, security::SecurityCredentials, BasicProperties
};
use std::thread;
use log::info;
use log::error;

use serde::{Deserialize, Serialize};

use crate::store;
use store::Store;

// #[derive(Clone)]
// struct RabbitMQClient {
//     conn: Connection,
//     chann: Channel
// }
const RMQ_FILES_QUEUE: &'static str = "rmq_file";

#[derive(Clone)]
struct ApiContext {
    rbmq: Channel,
    rbmq_files_queue: String
}
#[derive(Deserialize, Serialize)]
struct Response {
    msg: String,
}

pub trait ServerMethods<'a> {
    // async fn submit_file(self, multipart: Multipart) -> (StatusCode, Json<Response<'a>>) ;
    async fn start(self) -> anyhow::Result<()>;
}

pub struct Server<'a> {
    bindhost: &'a str,
    store: Store
}

impl<'a> Server<'a> {
    pub fn new(h: &'a str) -> Self {
        let store = Store::new("sqlite");
        Self {
            bindhost: h,
            store
        }
    }
}

async fn submit_file(Extension(ctx): Extension<ApiContext>, mut multipart: Multipart) -> impl IntoResponse {
    let mut file_name = String::new();
    let mut chunk_number = 0;
    let mut total_chunks = 0;
    let mut chunk_data = Vec::new();
    let mut total_file_bytes: Vec<u8> = Vec::new();
    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(Response { msg: format!("Error reading multipart field: {:?}", err) }))
        }
    } {
        let field_name = field.name().unwrap_or_default().to_string();
        match field_name.as_str() {
            "fileName" => file_name = field.text().await.unwrap_or_default(),
            "chunkNumber" => chunk_number = field.text().await.unwrap_or_default().parse().unwrap_or(0),
            "totalChunks" => total_chunks = field.text().await.unwrap_or_default().parse().unwrap_or(0),
            "chunk" => {
                chunk_data = field.bytes().await.unwrap_or_else(|_| {
                    error!("could not parse {:d} chunk of file", chunk_number);
                    Vec::new().into()
                }).to_vec();
                [&total_file_bytes[..], &chunk_data[..]].concat();
            },
            _ => {}
        }
    }

    let args = BasicPublishArguments::new(
        "amq.file_exchange",
        "amqprs.file_routing_key"
    );

    let rbmq_res = ctx.rbmq.basic_publish(BasicProperties::default(), chunk_data, args).await;
    info!("RabbitMQ message result: {:?}", rbmq_res);
    (StatusCode::CREATED, Json(Response { msg: "file was submitted".to_string()}))
}

impl<'a> ServerMethods<'a> for Server<'a> {
    // async 
    async fn start(self) -> anyhow::Result<()> {
        // // tracing_subscriber::fmt::init();
        // let args = OpenConnectionArguments::new("localhost", 5672, "user", "bitnami");
        // let connection = Connection::open(&args).await.unwrap();
        // connection.register_callback(callbacks::DefaultConnectionCallback).await.unwrap();

        let connection = Connection::open(&OpenConnectionArguments::new(
            "127.0.0.1",
            5672,
            "ruser",
            "rpassword",
        )).await.unwrap();
        connection
            .register_callback(DefaultConnectionCallback)
            .await
            .unwrap();
        let channel = connection.open_channel(None).await.unwrap();
        channel.register_callback(DefaultChannelCallback).await.unwrap();

        let (queue_name, _, _) = channel
            .queue_declare(QueueDeclareArguments::default())
            .await
            .unwrap()
            .unwrap();
        // channel.

        let routing_key = "amqprs.file_routing_key";
        let exchange_name = "amq.file_exchange";
        channel
            .queue_bind(QueueBindArguments::new(
                &queue_name,
                exchange_name,
                routing_key,
            ))
            .await
            .unwrap();

        thread::spawn(|| {
            loop {
                channel.co
            }
        })

        let app = Router::new().layer(
            Extension(ApiContext {
                rbmq: channel,
                rbmq_files_queue: queue_name
            })
        ).route("/upload_file", post(submit_file));

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
