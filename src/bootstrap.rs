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
