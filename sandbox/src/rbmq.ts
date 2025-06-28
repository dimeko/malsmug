import amqplib, { GetMessage } from 'amqplib';
import * as types from "./types";

class RBMQ {
    // not used at the moment
    private host: string;
    private port: number;
    private username: string;
    private password: string;

    private conn: amqplib.ChannelModel | null
    private channel: amqplib.Channel | null

    constructor(config: types.RabbitMQConfig) {
        this.host = config.connection.host
        this.port = config.connection.port
        this.username = config.connection.username
        this.password = config.connection.password
        this.conn = null
        this.channel = null
    }

    static async create(config: types.RabbitMQConfig): Promise<RBMQ> {
        const client = new RBMQ(config);
        await client.init();
        return client;
    } 

    private async init() {
        let connection_options: amqplib.Options.Connect = {
            hostname: "rabbitmq",
            port: 5672,
            protocol: "amqp",
            username: this.username,
            password: this.password
        }
        this.conn = await amqplib.connect(connection_options, "heartbeat=60")
        this.channel = await this.conn.createChannel();
    }

    async publish(queue: string, msg: any) {
        if(this.channel == null) return null
        await this.channel.assertQueue(queue, { durable: true, autoDelete: true });
        let json_data: string = JSON.stringify(msg)
        this.channel.sendToQueue(queue, Buffer.from(json_data));
    }

    // async consume(queue: string, cb: (bytesAsString: Buffer<ArrayBufferLike>) => void) {
    //     if(this.channel == null) return null
    //     await this.channel.assertQueue(queue, { durable: true, autoDelete: true });
    //     this.channel.get(queue, {
    //         noAck: false
    //     }).then(async (getMsg: GetMessage | false) => {
    //         if(!getMsg) {return} 
    //         await cb(getMsg.content)
    //         this.channel?.ack(getMsg, false)
    //     }).catch((err) => {
    //         console.log("[analysis-debug] Got error from queue: ", err)
    //     })
    // } 
}

export {
    RBMQ
}