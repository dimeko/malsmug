// import amqplib from "amqplib"
import amqplib, { GetMessage } from 'amqplib';

class RBMQ {
    private host: string;
    private conn: amqplib.ChannelModel | null
    private channel: amqplib.Channel | null

    // private exhange_name: string
    // private routing_key: string
    constructor(h: string, en: string, rk: string) {
        this.host = h
        // this.exhange_name = en;
        // this.routing_key = rk;

        this.conn = null
        this.channel = null
    }

    static async create(h: string, en: string, rk: string): Promise<RBMQ> {
        const client = new RBMQ(h,en,rk);
        await client.init();
        return client;
    } 

    private async init() {
        let connection_options: amqplib.Options.Connect = {
            hostname: this.host,
            port: 5672,
            protocol: "amqp",
            username: "ruser",
            password: "rpassword"
        }
        this.conn = await amqplib.connect(connection_options, "heartbeat=60")
        this.channel = await this.conn.createChannel();
    }

    async publish(queue: string, message: any) {
        if(this.channel == null) return null
        await this.channel.assertQueue(queue, { durable: true, autoDelete: true });
        this.channel.sendToQueue(queue, Buffer.from("testing the sending bufefer"));
    }

    async consume(queue: string, cb: (bytesAsString: Buffer<ArrayBufferLike>) => void) {
        if(this.channel == null) return null
        await this.channel.assertQueue(queue, { durable: true, autoDelete: true });
        this.channel.get(queue, {
            noAck: false
        }).then(async (getMsg: GetMessage | false) => {
            if(!getMsg) {return} 
            await cb(getMsg.content)
            this.channel?.ack(getMsg, false)
        }).catch((err) => {
            console.log("[analysis-debug] Got error from queue: ", err)
        })
        // await this.channel.consume(
        //     queue,
        //     async (msg) => {
        //         if(msg == null) return;
        //         await cb(msg.content)
        //     },
            
        // )
    } 
}

export {
    RBMQ
}