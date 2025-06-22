// import amqplib from "amqplib"
import amqplib from 'amqplib';

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
        this.conn = await amqplib.connect("amqp://" + this.host , "heartbeat=60")
        this.channel = await this.conn.createChannel();
    }

    async publish(queue: string, message: any) {
        if(this.channel == null) return null
        await this.channel.assertQueue(queue, { durable: true });
        this.channel.sendToQueue(queue, Buffer.from(message));
    }

    async consume(queue: string, cb: (bytesAsString: Buffer<ArrayBufferLike>) => void) {
        if(this.channel == null) return null
        await this.channel.assertQueue(queue, { durable: true });
        await this.channel.consume(
            queue,
            (msg) => {
                if(msg == null) return;
                cb(msg.content)
            }
        )
    } 
}

export {
    RBMQ
}