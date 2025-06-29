use anyhow::Error;
use lapin::{
    options::{
        BasicConsumeOptions,
        BasicPublishOptions,
        ExchangeDeclareOptions,
        QueueBindOptions,
        QueueDeclareOptions
    }, publisher_confirm::PublisherConfirm, tcp::OwnedTLSConfig, types::FieldTable, uri::{self, AMQPUri}, BasicProperties, Channel, Connection, ConnectionProperties, Consumer
};
use log::error;

use crate::bootstrap::rabbitmq_conf;
use async_trait::async_trait;

#[async_trait]
pub trait Queue: Sync + Send {
    async fn consume(&self, queue: &str) -> Result<Consumer, Error>;
    async fn publish(&self, queue: &str, exchange: &str, data: Vec<u8>) -> Result<PublisherConfirm, Error>;
    fn get_core_files_queue(&self) -> &str;
    fn get_sandbox_iocs_queue(&self) -> &str;
    fn get_main_exchange(&self) -> &str;
}

#[derive(Clone)]
pub struct RabbitMQueueConf {
    name: String,
    durable: bool,
    auto_delete: bool
}

impl RabbitMQueueConf {
    fn new(extc: rabbitmq_conf::RabbitMQExtQueueConf) -> Self {
        RabbitMQueueConf {
            name: extc.name,
            durable: extc.durable,
            auto_delete: extc.auto_delete
        }
    }
}

#[derive(Clone)]
pub struct RabbitMQExchangeConf {
    name: String,
}

impl RabbitMQExchangeConf {
    fn new(extc: rabbitmq_conf::RabbitMQExtExchangeConf) -> Self {
        RabbitMQExchangeConf {
            name: extc.name,
        }
    }
}


#[derive(Clone)]
pub struct RabbitMQConfig {
    core_files_queue: RabbitMQueueConf,
    sandbox_iocs_queue: RabbitMQueueConf,
    main_exchange: RabbitMQExchangeConf
}

impl RabbitMQConfig {
    pub fn new(extc: rabbitmq_conf::RabbitMQExtConf) -> Self {
        RabbitMQConfig {
            core_files_queue: RabbitMQueueConf::new(extc.queues.core_files_queue),
            sandbox_iocs_queue: RabbitMQueueConf::new(extc.queues.sandbox_iocs_queue),
            main_exchange: RabbitMQExchangeConf::new(extc.exchanges.main_exchange),
        }
    }
}

// #[derive(Clone)]
pub struct RabbitMQ {
    conn: Connection,
    channel: Channel,
    conf: RabbitMQConfig
}

impl RabbitMQ {
    pub async fn new(host: String, port: u16, user: String, pass: String, conf: RabbitMQConfig) -> Self {
         let conn = Connection::connect_uri_with_config(
            AMQPUri {
                scheme: uri::AMQPScheme::AMQP,
                authority: uri::AMQPAuthority {
                    userinfo: uri::AMQPUserInfo { username: user, password: pass },
                    host,
                    port
                },
                vhost: "/".to_string(),
                query: uri::AMQPQueryString::default()
            },
            ConnectionProperties::default(),
            OwnedTLSConfig::default()
        ).await.unwrap();

        let channel = conn.create_channel().await.unwrap();
        let s = RabbitMQ {
            conf,
            conn: conn,
            channel: channel,
        };

        s.init().await;
        s
    }

    pub async fn init(&self) {
        // Initialization of main_exchange
        let exchange_args = ExchangeDeclareOptions {
            auto_delete: true,
            passive: false,
            durable: true,
            internal: false,
            nowait: false
        };

        let _ = self.channel.exchange_declare(
            &self.conf.main_exchange.name,
            lapin::ExchangeKind::Direct, exchange_args, FieldTable::default()).await;
            
        let queue_declare_args = QueueDeclareOptions {
            auto_delete: self.conf.core_files_queue.auto_delete,
            passive: false,
            durable: self.conf.core_files_queue.durable,
            exclusive: false,
            nowait: false
        };

        // Initialization of core_files_queue
        let _ = self.channel.queue_declare(
                &self.conf.core_files_queue.name,
                queue_declare_args,
                FieldTable::default(),
            )
            .await.unwrap();

        // Initialization of sandbox_iocs_queue
        let _ = self.channel.queue_declare(
                &self.conf.sandbox_iocs_queue.name,
                queue_declare_args,
                FieldTable::default(),
            )
            .await.unwrap();

        let queue_bind_args = QueueBindOptions {
            nowait: false
        };
        let _ = self.channel.queue_bind(
            &self.conf.core_files_queue.name,
            &self.conf.main_exchange.name,
            &self.conf.core_files_queue.name,
            queue_bind_args, FieldTable::default()).await;
        let _ = self.channel.queue_bind(
            &self.conf.sandbox_iocs_queue.name,
            &self.conf.main_exchange.name,
            &self.conf.core_files_queue.name,
            queue_bind_args, FieldTable::default()).await;
    }
}

#[async_trait]
impl Queue for RabbitMQ {
    async fn consume(&self, queue: &str) -> Result<Consumer, Error> {
        let consume_args = BasicConsumeOptions {
            no_ack: false,
            no_local: true,
            exclusive: true,
            nowait: false
        };
        match self.channel.basic_consume(queue, "rbclient", consume_args, FieldTable::default()).await {
            Ok(c) => {
                return Ok(c);
            },
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    async fn publish(&self, queue: &str, exchange: &str, data: Vec<u8>) -> Result<PublisherConfirm, Error> {
        match self.channel.basic_publish(
            exchange,
            queue,
            BasicPublishOptions::default(),
            &data,
            BasicProperties::default()).await {
            Ok(r) => {
                return Ok(r);
            },
            Err(e) => {
                error!("could not publish: {:?}", e);
                return Err(e.into());
            }
        }
    }

    fn get_core_files_queue(&self) -> &str {
        self.conf.core_files_queue.name.as_str()
    }

    fn get_sandbox_iocs_queue(&self) -> &str {
        self.conf.sandbox_iocs_queue.name.as_str()
    }

    fn get_main_exchange(&self) -> &str {
        self.conf.main_exchange.name.as_str()
    }
}
