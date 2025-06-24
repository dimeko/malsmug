
use std::{fmt::format, time::{self, Duration}};
use tokio::task;
use async_std::stream::StreamExt;
use axum::{
    extract::Multipart, http::StatusCode, middleware::AddExtension, response::IntoResponse, routing::{get, post}, Extension, Json, Router
};
use amqprs::{
    callbacks::{DefaultChannelCallback, DefaultConnectionCallback}, channel::{BasicAckArguments, BasicConsumeArguments, BasicGetArguments, BasicPublishArguments, Channel, ExchangeBindArguments, ExchangeDeclareArguments, QueueBindArguments, QueueDeclareArguments}, connection::{Connection, OpenConnectionArguments}, consumer::{self, BlockingConsumer, DefaultBlockingConsumer, DefaultConsumer}, security::SecurityCredentials, AmqpDeliveryTag, BasicProperties
};
use std::thread;
use log::{debug, info, warn};
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
    // async fn upload_file(self, multipart: Multipart) -> (StatusCode, Json<Response<'a>>) ;
    async fn start(self) -> anyhow::Result<()>;
}

pub struct Server<'a> {
    bindhost: &'a str,
    store: Store
}

impl<'a> Server<'a> {
    pub async fn new(h: &'a str) -> Self {
        let store = Store::new("sqlite").await;
        Self {
            bindhost: h,
            store
        }
    }
}

async fn upload_file(Extension(ctx): Extension<ApiContext>, mut multipart: Multipart) -> impl IntoResponse {
    // let mut total_chunks = 0;
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
                let file_name = field.name().unwrap().to_string(); 
                debug!("file name: {}", file_name);
                total_file_bytes = field.bytes().await.unwrap().to_vec();
                // info!("total_file_bytes: {:?}", total_file_bytes);
            },
            // "chunkNumber" => {
            //     chunk_number = field.text().await.unwrap_or_default().parse().unwrap_or(0);
            //     debug!("chunk number: {}", chunk_number);
            // },
            // // "totalChunks" => total_chunks = field.text().await.unwrap_or_default().parse().unwrap_or(0),
            // "chunk" => {
            //     chunk_data = field.bytes().await.unwrap_or_else(|_| {
            //         error!("could not parse {} chunk of file", chunk_number);
            //         Vec::new().into()
            //     }).to_vec();
            //     total_file_bytes = [&total_file_bytes[..], &chunk_data[..]].concat();
            //     debug!("total bytes number: {}", total_file_bytes.len());

            // },
            _ => {}
        }
    }

    let args = BasicPublishArguments::new(
        "malsmug.analysis",
        &ctx.rbmq_files_queue
    );

    let rbmq_res = ctx.rbmq.basic_publish(BasicProperties::default(), total_file_bytes, args).await.unwrap();

    // let args2 = BasicAckArguments::new(
    //     1 as AmqpDeliveryTag,
    //     true
    // );
    // ctx.rbmq.basic_ack(args2).await.unwrap()
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

        connection.register_callback(DefaultConnectionCallback)
            .await
            .unwrap();

        let channel = connection.open_channel(None).await.unwrap();

        channel.register_callback(DefaultChannelCallback).await.unwrap();

        let queue_declare_args = QueueDeclareArguments::durable_client_named("malsmug.files_queue").auto_delete(true).to_owned();

        let (queue_name, _, _) = channel.queue_declare(queue_declare_args)
            .await
            .unwrap()
            .unwrap();
    
        let queue2_declare_args = QueueDeclareArguments::durable_client_named("malsmug.reports_queue").auto_delete(true).to_owned();

        let (_, _, _) = channel.queue_declare(queue2_declare_args)
            .await
            .unwrap()
            .unwrap();


        let exchange_name = "malsmug.analysis";
        let exchange_args = ExchangeDeclareArguments::new(
            exchange_name,  
            "direct");
        let _ = channel.exchange_declare(exchange_args).await;

        // let routing_key = "amqprs.file_routing_key";

        channel.queue_bind(QueueBindArguments::new(
                &queue_name,
                exchange_name,
                &queue_name,
            ))
            .await
            .unwrap();

        let _ = task::spawn(async move {
            connection.register_callback(DefaultConnectionCallback)
                .await
                .unwrap();

            let channel2 = connection.open_channel(None).await.unwrap();

            let basic_consume_args = BasicConsumeArguments::new(
                "malsmug.reports_queue",
                "basic_pub_sub"
            );

            // let queue_bind_args = QueueBindArguments::new(
            //     "malsmug.reports_queue",exchange_name,"malsmug.reports_queue"
            // );
            // channel2.queue_bind(queue_bind_args);
            let basic_get_args = BasicGetArguments::new(
                "malsmug.reports_queue"
            );
            loop {
                
                let _ = match channel2.basic_get(basic_get_args.clone()).await.unwrap(){
                    Some(_r) => {
                        info!("Got report for file: {:?}", _r.1.headers());
                        info!("-  {:?}", _r.2);
                        let basic_ack_args = BasicAckArguments::new(
                            0, true);
                        let _ = channel2.basic_ack(basic_ack_args).await;
                    },
                    None => {
                        warn!("Got report answer for None");
                    }
                };
                // info!("analysis results: {:?}", res);
                // consumer.
                thread::sleep(time::Duration::from_secs(1));
            }
        });

        let app = Router::new()
            .route("/upload_file", post(upload_file))
            .route_layer(
                Extension(ApiContext {
                    rbmq: channel,
                    rbmq_files_queue: queue_name
                })
            );

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
