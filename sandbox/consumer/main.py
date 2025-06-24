from pika import ConnectionParameters, PlainCredentials, BlockingConnection
from argparse import ArgumentParser
from pathlib import Path
import hashlib
# from multiprocessing import Pool
import subprocess

def run(samples_dir="", sandbox_lib="", bait_website=""):
    print("running consumer")
    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    
    print("samples dir:", samples_dir)
    print("sandbox dir:", sandbox_lib)
    print("bait website:", bait_website)

    # channel, method, properties, body
    def on_message(channel, method, props, body):
        print("Got message")
        m = hashlib.sha256()
        m.update(body)
        digest = m.hexdigest()
        
        samples_file_path = samples_dir + "/" + digest
        with open(samples_file_path, "w") as f:
            f.write(body.decode("utf-8"))
        channel.basic_ack(delivery_tag=method.delivery_tag)

        print("file was created: ", samples_file_path)
        subprocess.Popen(
            ["node", sandbox_lib, samples_file_path, bait_website],
            stdin=None, stdout=None, stderr=None)
        
        # pool.apply_async(proc)
        
    conn_params = ConnectionParameters(
        host="rabbitmq",
        port=5672,
        credentials=PlainCredentials(
            username="ruser",
            password="rpassword",
            erase_on_connect=True
        )
    )
    connection = BlockingConnection(conn_params)
    channel = connection.channel()
    channel.queue_declare(queue="malsmug.files_queue", durable=True, auto_delete=True)
    channel.queue_bind(exchange='malsmug.analysis', queue='malsmug.files_queue', routing_key='malsmug.files_queue')
    print("start consuming from RabbitMQ")
    while True:
        try:
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='malsmug.files_queue', on_message_callback=on_message)
            channel.start_consuming()
        except Exception as err:
            print("Error while consuming: ", err)
            if channel.is_closed():
                print("Bye!")
                break


if __name__ == "__main__":
    parser = ArgumentParser(
                    prog='Sandbox',
                    description='RabbitMQ consumer')
    
    parser.add_argument('--samples-dir', default="./samples")
    parser.add_argument('--sandbox-lib', default="/sandbox/lib/app.js")
    parser.add_argument('--bait-website', default="https://facebook.com")

    args = parser.parse_args()
    print("Parsed flags: ", args)
    run(
        samples_dir=args.samples_dir,
        sandbox_lib=args.sandbox_lib,
        bait_website=args.bait_website
    )