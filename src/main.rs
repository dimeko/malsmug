use std::path::PathBuf;
use clap::{Parser};
use log::info;
use env_logger::Builder;

mod store;
mod utils;
mod app;
mod analysis;
mod bootstrap;

use app::ServerMethods;
use app::rabbitclient;

#[derive(Parser)]
struct Args {
    #[clap(long)]
    bindhost: String,
    #[clap(long)]
    bindport: u16,
    #[clap(
        long,
        short,
        default_missing_value("true"),
        default_value("false"),
    )]
    verbose: bool,
    #[clap(
        long,
        short,
        default_missing_value("true"),
        default_value("false"),
    )]
    debug: bool
}

#[tokio::main]
async fn main() {
    let mut builder = Builder::from_default_env();

    let mut log_level: log::LevelFilter = log::LevelFilter::Debug;
    let cli_args = Args::parse();

    if cli_args.verbose {
        log_level = log::LevelFilter::Info;
    }

    if cli_args.debug {
        log_level = log::LevelFilter::Debug;
    }

    builder
        .filter(None, log_level)
        .init();

    let server_address= cli_args.bindhost + ":" + &cli_args.bindport.to_string();

    let rbmq_conf_from_file = utils::parse_yaml::
        <bootstrap::rabbitmq_conf::RabbitMQExtConf>(PathBuf::from("./config/rabbitmq.yaml")).unwrap(); 

    info!("running server on {}", server_address);

    let rbmqc = rabbitclient::RabbitMQ::new(
        rbmq_conf_from_file.connection.host.clone(),
        rbmq_conf_from_file.connection.host_port.clone(),
        rbmq_conf_from_file.connection.username.clone(),
        rbmq_conf_from_file.connection.password.clone(),
        rabbitclient::RabbitMQConfig::new(rbmq_conf_from_file)
    ).await;
    let s = app::Server::new(&server_address, Box::new(rbmqc)).await;

    let _ = s.start().await;
}
