from dataclasses import dataclass
from pika import ConnectionParameters, PlainCredentials, BlockingConnection
from argparse import ArgumentParser
from pathlib import Path
import hashlib
import msgpack
# from multiprocessing import Pool
import subprocess
import time

# Rust struct reference
# pub struct FileForAnalysis {
#     pub file_name: String,
#     pub file_hash: String,
#     pub file_bytes: Vec<u8>
# }

@dataclass
class FileForAnalysis:
    file_name: str
    file_hash: str
    file_bytes: bytes
        
def run(samples_dir="", sandbox_lib="", bait_website=""):
    print("running consumer")
    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    
    print("samples dir:", samples_dir)
    print("sandbox dir:", sandbox_lib)
    print("bait website:", bait_website)

    # channel, method, properties, body
    def on_message(channel, method, props, body):
        try:
            print("Got message")
            # m = hashlib.sha256()
            # m.update(body)
            # digest = m.hexdigest()
            
            try:
                file_for_analysis_raw = msgpack.unpackb(body)
                
                file_for_analysis = FileForAnalysis(
                    file_name=file_for_analysis_raw[0],
                    file_hash=file_for_analysis_raw[1],
                    file_bytes=file_for_analysis_raw[2]
                )
            except msgpack.FormatError as e:
                print("data received from queue is not valid msgpack bytes")
                return
            
            print("file_for_analysis: ", file_for_analysis.file_name)
            if isinstance(file_for_analysis, FileForAnalysis):
                samples_file_path = samples_dir + "/" + file_for_analysis.file_hash
                with open(samples_file_path, "w") as f:
                    byte_string = ""
                    for b in file_for_analysis.file_bytes:
                        byte_string = byte_string + chr(b)
                    f.write(byte_string)
                channel.basic_ack(delivery_tag=method.delivery_tag)

                print("file was created: ", samples_file_path)
                subprocess.Popen(
                    ["node", sandbox_lib, samples_file_path, bait_website],
                    stdin=None, stdout=None, stderr=None)
        except Exception as e:
            print("error processing message: ", e)
        
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
    while True:
        try:
            connection = BlockingConnection(conn_params)
            channel = connection.channel()
            channel.queue_declare(queue="malsmug.files_for_analysis", durable=True, auto_delete=True)
            channel.queue_bind(exchange='malsmug.analysis', queue='malsmug.files_for_analysis', routing_key='malsmug.files_for_analysis')
            break
        except Exception as e:
            sec = 5
            print(f"error connecting, trying again in {sec} ...")
            time.sleep(sec)
        
    print("start consuming from RabbitMQ")
    while True:
        try:
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue='malsmug.files_for_analysis', on_message_callback=on_message)
            channel.start_consuming()
        except Exception as err:
            print("Error while consuming: ", err)
            if channel.is_closed:
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