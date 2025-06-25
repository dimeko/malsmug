use amqprs::{
    callbacks::{DefaultChannelCallback, DefaultConnectionCallback}, channel::{BasicAckArguments, BasicConsumeArguments, BasicGetArguments, BasicPublishArguments, Channel, ExchangeBindArguments, ExchangeDeclareArguments, QueueBindArguments, QueueDeclareArguments}, connection::{Connection, OpenConnectionArguments}, consumer::{self, AsyncConsumer, BlockingConsumer, DefaultBlockingConsumer, DefaultConsumer}, security::SecurityCredentials, AmqpDeliveryTag, BasicProperties, Deliver
};
use async_trait::async_trait;

#[async_trait]
trait QueueActions {
    async fn consume(self, queue: String, callback: fn());
    async fn publish(self, queue: String, exchange: String, data: Vec<u8>);
}

struct RabbitMQueueConf {
    name: String,
    durable: bool,
    auto_delete: bool
}

struct RabbitMQExchangeConf {
    name: String,
}

struct RabbitMQConfig {
    core_files_queue: RabbitMQueueConf,
    sandbox_iocs_queue: RabbitMQueueConf,
    main_exchange: RabbitMQExchangeConf
}

struct RabbitMQ {
    host: String,
    port: u16,
    conn: Connection,
    channel: Channel,
    conf: RabbitMQConfig
}

impl RabbitMQ {
    pub async fn new(host: String, port: u16, user: String, pass: String, conf: RabbitMQConfig) -> Self {
        let connection = Connection::open(&OpenConnectionArguments::new(
            &host,
            port,
            &user,
            &pass,
        )).await.unwrap();

        connection.register_callback(DefaultConnectionCallback)
            .await
            .unwrap();
        
        let channel = connection.open_channel(None).await.unwrap();
        channel.register_callback(DefaultChannelCallback).await.unwrap();

        RabbitMQ {
            host,
            port,
            conf,
            conn: connection,
            channel: channel,
        }
    }

    pub async fn init(self) {
        // Initialization of main_exchange
        let exchange_args = ExchangeDeclareArguments::new(
            &self.conf.main_exchange.name,  
            "direct");
        let _ = self.channel.exchange_declare(exchange_args).await;
            
        // Initialization of core_files_queue
        let queue_declare_args0 = QueueDeclareArguments::new(&self.conf.core_files_queue.name)
            .auto_delete(self.conf.core_files_queue.auto_delete)
            .durable(self.conf.core_files_queue.durable)
            .to_owned();
        let (_, _, _) = self.channel.queue_declare(queue_declare_args0)
            .await
            .unwrap()
            .unwrap();

        // Initialization of sandbox_iocs_queue
        let queue_declare_args1 = QueueDeclareArguments::new(&self.conf.sandbox_iocs_queue.name)
            .auto_delete(self.conf.sandbox_iocs_queue.auto_delete)
            .durable(self.conf.sandbox_iocs_queue.durable)
            .to_owned();
        let (_, _, _) = self.channel.queue_declare(queue_declare_args1)
            .await
            .unwrap()
            .unwrap();

        self.channel.queue_bind(QueueBindArguments::new(
                &self.conf.core_files_queue.name,
                &self.conf.main_exchange.name,
                &self.conf.core_files_queue.name,
            ))
            .await
            .unwrap();
    }
}

struct _CoreConsumer;

impl AsyncConsumer for _CoreConsumer {
    async fn consume(
        &mut self, // use `&mut self` to make trait object to be `Sync`
        channel: &Channel,
        deliver: Deliver,
        basic_properties: BasicProperties,
        content: Vec<u8>,
    ) {

    }
}

#[async_trait]
impl QueueActions for RabbitMQ {
    pub async fn consume(self, queue: String, callback: fn()) {
        let consume_args = BasicConsumeArguments::new(&queue, "rbmq_core_client");
        self.channel.basic_consume(, args)
    }

    pub async fn publish(self, queue: String, exchange: String, data: Vec<u8>) -> Result<(), Error>{
        let args = BasicPublishArguments::new(
            &exchange,
            &queue
        );
        self.channel.basic_publish(BasicProperties::default(), data, args).await
    }
}
