import os
from dataclasses import dataclass
from pika import ConnectionParameters, PlainCredentials, BlockingConnection
from argparse import ArgumentParser
from pathlib import Path
import msgpack
import subprocess
import time
from datetime import datetime
import yaml
import logging

logger = logging.getLogger(__name__)

def validate_log_level(lv: str) -> str:
    if lv == 'debug': return logging.DEBUG
    elif lv == 'info': return logging.INFO
    elif lv == 'warn': return logging.WARN
    elif lv == 'warning': return logging.WARN
    elif lv == 'error': return logging.ERROR
    else: return logging.INFO

@dataclass
class FileForAnalysis:
    file_name: str
    file_hash: str
    analysis_id: str
    bait_websites: list[str]
    file_bytes: bytes
        
def run(samples_dir="", sandbox_lib="", config_folder="", bait_website=""):
    logger.info("running consumer ...")
    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    
    logger.debug("samples dir:", samples_dir)
    logger.debug("sandbox dir:", sandbox_lib)
    logger.debug("config folder: ", config_folder)
    logger.debug("bait website:", bait_website)

    def on_message(channel, method, _, body):
        try:
            try:
                file_for_analysis_raw = msgpack.unpackb(body)                
                file_for_analysis = FileForAnalysis(
                    file_name=file_for_analysis_raw[0],
                    file_hash=file_for_analysis_raw[1],
                    analysis_id=file_for_analysis_raw[2],
                    bait_websites=file_for_analysis_raw[3],
                    file_bytes=file_for_analysis_raw[4]
                )
            except msgpack.FormatError as e:
                logger.warning("data received from queue is not valid msgpack bytes")
                return
            
            logger.debug("file_for_analysis: ", file_for_analysis.file_name)
            if isinstance(file_for_analysis, FileForAnalysis):
                channel.basic_ack(delivery_tag=method.delivery_tag)
                # retrieving the current time and using it later in microseconds precision
                # because the same consumer creates multiple copies of the same file for analysis
                # on the same filesystem. The analyser removes the sample after analysis so we 
                # must create a dedicated sample copy for every analyser to avoid having to deal
                # with selective sample copy deletion
                dt = datetime.now()

                # looping with index
                for idx, bw in enumerate(file_for_analysis.bait_websites):

                    # adding the index of the loop as suffix to create different files for every analysis
                    # this does not mess with the javascript analyzer state and makes the analyses independent
                    samples_file_path = samples_dir + "/" + file_for_analysis.file_hash + "_" + str(dt.microsecond) + "_" + str(idx)
                    with open(samples_file_path, "w") as f:
                        byte_string = ""
                        for b in file_for_analysis.file_bytes:
                            byte_string = byte_string + chr(b)
                        f.write(byte_string)
                    subprocess.Popen(
                        ["node", sandbox_lib, samples_file_path, bw, config_folder, file_for_analysis.analysis_id],
                        stdin=None, stdout=None, stderr=None)
        except Exception as e:
            logger.error("error processing message: ", e)
        
    config = {}
    with open("/sandbox/config/rabbitmq.yaml", "r") as f:
        config = yaml.safe_load(f)

    try:
        conn_params = ConnectionParameters(
            host="rabbitmq",
            port=5672,
            credentials=PlainCredentials(
                username=config["connection"]["username"],
                password=config["connection"]["password"],
                erase_on_connect=True
            )
        )
    except Exception as e:
        logger.error("could not load configuration")
        os._exit(1)
        
    while True:
        try:
            connection = BlockingConnection(conn_params)
            channel = connection.channel()
            channel.queue_declare(
                queue=config["queues"]["core_files_queue"]["name"],
                durable=True,
                auto_delete=True)
            channel.queue_bind(
                exchange=config["exchanges"]["main_exchange"]["name"],
                queue=config["queues"]["core_files_queue"]["name"],
                routing_key=config["queues"]["core_files_queue"]["name"])
            break
        except Exception as e:
            sec = 5
            logger.error(f"error connecting, trying again in {sec} ...")
            time.sleep(sec)
        
    logger.info("start consuming from RabbitMQ")
    while True:
        try:
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(
                queue=config["queues"]["core_files_queue"]["name"],
                on_message_callback=on_message
            )

            channel.start_consuming()
        except Exception as err:
            logger.error("Error while consuming: ", err)
            if channel.is_closed:
                logger.info("Bye!")
                break

if __name__ == "__main__":
    logger.setLevel(validate_log_level(os.environ['LOG_LEVEL']))
    parser = ArgumentParser(
                    prog='Sandbox',
                    description='RabbitMQ consumer')
    
    parser.add_argument('--samples-dir', default="./samples")
    parser.add_argument('--sandbox-lib', default="/sandbox/lib/app.js")
    parser.add_argument('--config-folder', default="/sandbox/config")
    parser.add_argument('--bait-website', default="https://facebook.com")

    args = parser.parse_args()
    logger.info("parsed flags: ", args)
    run(
        samples_dir=args.samples_dir,
        sandbox_lib=args.sandbox_lib,
        config_folder=args.config_folder,
        bait_website=args.bait_website
    )