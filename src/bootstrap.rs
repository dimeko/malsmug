pub mod rabbitmq_conf {
    use serde::{Serialize, Deserialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RabbitMQExtHostConf {
        pub host: String,
        pub docker: String,
        pub host_port: u16,
        pub docker_port: u16
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
        pub host: RabbitMQExtHostConf,
        pub queues: RabbitMQExtQueuesConf,
        pub exchanges: RabbitMQExtExchangesConf
    }
}
