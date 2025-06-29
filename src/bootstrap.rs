use std::path::PathBuf;

use crate::{app::{self, rabbitclient, App}, bootstrap::rabbitmq_conf::RabbitMQExtConf, utils, Args};

pub mod rabbitmq_conf {
    use serde::{Serialize, Deserialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtConnectionConf {
        pub host: String,
        pub host_port: u16,
        pub username: String,
        pub password: String
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtQueueConf {
        pub name: String,
        pub durable: bool,
        pub auto_delete: bool
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtExchangeConf {
        pub name: String
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtQueuesConf {
        pub core_files_queue: RabbitMQExtQueueConf,
        pub sandbox_iocs_queue: RabbitMQExtQueueConf,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtExchangesConf {
        pub main_exchange: RabbitMQExtExchangeConf,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtConf {
        pub connection: RabbitMQExtConnectionConf,
        pub queues: RabbitMQExtQueuesConf,
        pub exchanges: RabbitMQExtExchangesConf
    }
}

pub async fn bootstrap(args: Args) -> App {
    let server_address: String = args.bindhost + ":" + args.bindport.to_string().as_str();

    let rbmq_conf_from_file = utils::parse_yaml::
        <RabbitMQExtConf>(PathBuf::from("./config/rabbitmq.yaml")).unwrap(); 

    println!("running server on {}", server_address.clone());

    let rbmqc = rabbitclient::RabbitMQ::new(
        rbmq_conf_from_file.connection.host.clone(),
        rbmq_conf_from_file.connection.host_port.clone(),
        rbmq_conf_from_file.connection.username.clone(),
        rbmq_conf_from_file.connection.password.clone(),
        rabbitclient::RabbitMQConfig::new(rbmq_conf_from_file)
    ).await;

    app::App::new(server_address, Box::new(rbmqc)).await
}