// use amqprs::{
//     callbacks::{DefaultChannelCallback, DefaultConnectionCallback}, channel::{
//         BasicAckArguments,
//         BasicConsumeArguments,
//         BasicPublishArguments,
//         Channel,
//         ExchangeDeclareArguments,
//         QueueBindArguments,
//         QueueDeclareArguments}, connection::{
//         Connection,
//         OpenConnectionArguments}, consumer::{
//         AsyncConsumer, DefaultConsumer
//     }, error::Error, BasicProperties, Deliver
// };
use lapin::{
    options::{
        ExchangeDeclareOptions,
        QueueBindOptions,
        QueueDeclareOptions},
    types::FieldTable,
    Channel,
    Connection,
    ConnectionProperties
};
use log::{debug, info, error};

use crate::bootstrap::rabbitmq_conf;
use async_trait::async_trait;

#[async_trait]
pub trait Queue: Sync + Send {
    async fn consume(&self, queue: &str, callback: fn(c: Vec<u8>));
    async fn publish(&self, queue: &str, exchange: &str, data: Vec<u8>) -> Result<(), Error>;
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

#[derive(Clone)]
pub struct RabbitMQ {
    host: String,
    port: u16,
    conn: Connection,
    channel: Channel,
    conf: RabbitMQConfig
}

impl RabbitMQ {
    pub async fn new(host: String, port: u16, user: String, pass: String, conf: RabbitMQConfig) -> Self {
        // let connection = Connection::open(&OpenConnectionArguments::new(
        //     &host,
        //     port,
        //     &user,
        //     &pass,
        // )).await.unwrap();
         let conn = Connection::connect(
            "ampq://127.0.0.1:5672".into(),// + host.as_str() + ":" + port.to_string()).into(),
            ConnectionProperties::default(),
        )
        .await.unwrap();
        let channel = conn.create_channel().await.unwrap();
        // connection.register_callback(DefaultConnectionCallback)
        //     .await
        //     .unwrap();
        
        // let channel = connection.open_channel(None).await.unwrap();
        // channel.register_callback(DefaultChannelCallback).await.unwrap();
        // let queue = channel
        //     .queue_declare(
        //         "hello",
        //         QueueDeclareOptions::default(),
        //         FieldTable::default(),
        //     )
        //     .await?;
        let s = RabbitMQ {
            host,
            port,
            conf,
            conn: conn,
            channel: channel,
        };

        s.init().await;
        s
    }

    pub async fn init(&self) {
        // Initialization of main_exchange
        // let exchange_args = ExchangeDeclareArguments::new(
        //     &self.conf.main_exchange.name,  
        //     "direct");
        let exchange_args = ExchangeDeclareOptions {
            auto_delete: true,
            passive: true,
            durable: true,
            internal: false,
            nowait: false
        };
        // let _ = self.channel.exchange_declare(exchange_args).await;
        self.channel.exchange_declare(
            &self.conf.main_exchange.name,
            lapin::ExchangeKind::Direct, exchange_args, FieldTable::default());
            
        let queue_declare_args = QueueDeclareOptions {
            auto_delete: true,
            passive: true,
            durable: true,
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
        self.channel.queue_bind(
            &self.conf.core_files_queue.name,
            &self.conf.main_exchange.name,
            &self.conf.core_files_queue.name,
            queue_bind_args, FieldTable::default());
    }
}

// struct _CoreConsumer(fn(c: Vec<u8>));

// #[async_trait]
// impl AsyncConsumer for _CoreConsumer {
//     async fn consume(
//         &mut self, // use `&mut self` to make trait object to be `Sync`
//         channel: &Channel,
//         deliver: Deliver,
//         basic_properties: BasicProperties,
//         content: Vec<u8>,
//     ) {
//         debug!("consumer called");
//         (self.0)(content);
//         let basic_ack_args = BasicAckArguments::new(
//             deliver.delivery_tag(), true);
//         let _ = channel.basic_ack(basic_ack_args);
//     }
// }

#[async_trait]
impl Queue for RabbitMQ {
    async fn consume(&self, queue: &str, callback: fn(c: Vec<u8>)) {
        debug!("calling main consume");
        let consume_args = BasicConsumeArguments::new(&queue, "cclient")
            .manual_ack(false).finish();
        let deliveries = self.channel.basic_consume(DefaultConsumer::new(consume_args.no_ack), consume_args).await.unwrap();
        while let Some(delivery) = deliveries.().await {
        match delivery {
            Ok(msg) => {
                callback(msg.data); // call your handler
            }
            Err(e) => {
                error!("Failed to receive message: {:?}", e);
                break;
            }
        }
    }
// }
//         match res {
//             Ok(r) => {
//                 info!("result from consumer: {:?}", r)
//             },
//             Err(e) => {
//                 error!("error from consumer: {:?}", e);
//             }
//         }
    }

    async fn publish(&self, queue: &str, exchange: &str, data: Vec<u8>) -> Result<(), Error> {
        let args: BasicPublishArguments = BasicPublishArguments::new(
            &exchange,
            &queue
        );
        self.channel.basic_publish(BasicProperties::default(), data, args).await
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
