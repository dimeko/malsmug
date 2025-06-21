
use axum::{
    extract::Multipart, http::StatusCode, middleware::AddExtension, response::IntoResponse, routing::{get, post}, Json, Router
};
use amqprs::{
    callbacks,
    security::SecurityCredentials,
    connection::{OpenConnectionArguments, Connection},
};
use serde::{Deserialize, Serialize};

// #[derive(Clone)]
// struct ApiContext {
//     rbmq: _,
// }

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
}

impl<'a> Server<'a> {
    pub fn new(h: &'a str) -> Self {
        Self {
            bindhost: h,
        }
    }
}

async fn submit_file(mut multipart: Multipart) -> impl IntoResponse {
    println!("submit_file");
    (StatusCode::CREATED, Json(Response { msg: "file was submitted".to_string()})) 
}

impl<'a> ServerMethods<'a> for Server<'a> {
    // async 
    async fn start(self) -> anyhow::Result<()> {
        // // tracing_subscriber::fmt::init();
        // let args = OpenConnectionArguments::new("localhost", 5672, "user", "bitnami");
        // let connection = Connection::open(&args).await.unwrap();
        // connection.register_callback(callbacks::DefaultConnectionCallback).await.unwrap();

        // let app = Router::new().layer(
        //     AddExtension::new(ApiC)
        // )
        let app = Router::new().route("/upload_file", post(submit_file));

        // run our app with hyper, listening globally on port 3000
        let listener = tokio::net::TcpListener::bind(self.bindhost).await.unwrap();
        axum::serve(listener, app).await.unwrap();
        Ok(())
    }
}
