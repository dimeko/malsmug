import os
import re
import signal
import uuid
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
import sys

logger = logging.getLogger(__name__)

# Hard limit for all analyses of one message (they run in parallel, one per bait website)
ANALYSIS_TIMEOUT_S = int(os.environ.get("ANALYSIS_TIMEOUT_S", "120"))
# Time node/puppeteer gets to close Chrome after SIGTERM before we SIGKILL
KILL_GRACE_S = 10

# Rust side: sha256::digest(...) -> lowercase hex, Uuid::new_v4().to_string()
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


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


def parse_message(body: bytes) -> FileForAnalysis:
    """Decode and validate a message. Raises ValueError on anything unexpected."""
    try:
        raw = msgpack.unpackb(body)
    except Exception as e:
        raise ValueError(f"not valid msgpack: {e}") from e

    # rmp_serde serializes the Rust struct as a 5-element array
    if not isinstance(raw, (list, tuple)) or len(raw) != 5:
        raise ValueError("expected a 5-element array")
    file_name, file_hash, analysis_id, bait_websites, file_bytes = raw

    if not isinstance(file_hash, str) or not SHA256_RE.match(file_hash):
        raise ValueError(f"invalid file_hash: {file_hash!r}")
    if not isinstance(analysis_id, str) or not UUID_RE.match(analysis_id):
        raise ValueError(f"invalid analysis_id: {analysis_id!r}")
    if not isinstance(bait_websites, list) or not bait_websites or not all(
        isinstance(w, str) and w.startswith(("http://", "https://")) for w in bait_websites
    ):
        raise ValueError(f"invalid bait_websites: {bait_websites!r}")
    # Vec<u8> arrives as a msgpack array of ints (or as bin if you ever add serde_bytes)
    if not isinstance(file_bytes, (list, bytes, bytearray)):
        raise ValueError("invalid file_bytes")
    try:
        file_bytes = bytes(file_bytes)
    except (TypeError, ValueError) as e:
        raise ValueError("invalid file_bytes") from e

    return FileForAnalysis(str(file_name), file_hash, analysis_id, bait_websites, file_bytes)

def kill_group(proc: subprocess.Popen) -> None:
    """SIGTERM the analysis process group (puppeteer closes Chrome on SIGTERM), then SIGKILL."""
    for sig, wait_s in ((signal.SIGTERM, KILL_GRACE_S), (signal.SIGKILL, None)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait_s)
            return
        except subprocess.TimeoutExpired:
            continue

def run_analyses(ffa: FileForAnalysis, samples_dir: str, sandbox_lib: str, config_folder: str) -> None:
    jobs = []
    for idx, bw in enumerate(ffa.bait_websites):
        # Unique copy per analysis: every analyser owns (and deletes) its own sample file
        sample_path = os.path.join(samples_dir, f"{ffa.file_hash}_{uuid.uuid4().hex}_{idx}")
        with open(sample_path, "wb") as f:
            f.write(ffa.file_bytes)

        cmd = [
            "node", sandbox_lib,
            # --opt=value form: a value can never be parsed as another flag (e.g. "--dev")
            f"--sample-file={sample_path}",
            f"--bait-website={bw}",
            f"--conf-folder={config_folder}",
            f"--analysis-id={ffa.analysis_id}",
        ]
        logger.info("running analysis command: %s", cmd)
        # Own process group, so a timeout can signal node and everything it started
        proc = subprocess.Popen(cmd, start_new_session=True)
        jobs.append((proc, sample_path, bw))

    deadline = time.monotonic() + ANALYSIS_TIMEOUT_S
    for proc, sample_path, bw in jobs:
        try:
            rc = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            if rc != 0:
                logger.warning("analysis %s on %s exited with code %s", ffa.analysis_id, bw, rc)
        except subprocess.TimeoutExpired:
            logger.warning("analysis %s on %s timed out after %ss, killing it",
                           ffa.analysis_id, bw, ANALYSIS_TIMEOUT_S)
            kill_group(proc)
        finally:
            # The analyser only deletes its sample on success; clean up failures/timeouts too
            Path(sample_path).unlink(missing_ok=True)



def run(samples_dir="", sandbox_lib="", config_folder=""):
    logger.info("running consumer ...")
    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    
    logger.debug("samples dir:", samples_dir)
    logger.debug("sandbox dir:", sandbox_lib)
    logger.debug("config folder: ", config_folder)

    def on_message(channel, method, _properties, body):
        try:
            ffa = parse_message(body)
        except ValueError as e:
            # Must reject: with prefetch_count=1 an unacked message blocks the consumer forever
            logger.warning("rejecting malformed message: %s", e)
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        logger.info("analysing %s (%s) on %d bait website(s)",
                    ffa.file_name, ffa.analysis_id, len(ffa.bait_websites))
        try:
            run_analyses(ffa, samples_dir, sandbox_lib, config_folder)
        except Exception:
            logger.exception("error running analyses for %s", ffa.analysis_id)
        # Ack only after the work is done: if the container dies mid-analysis, it is redelivered
        channel.basic_ack(delivery_tag=method.delivery_tag)

    with open(os.path.join(config_folder, "rabbitmq.yaml"), "r") as f:
        config = yaml.safe_load(f)

    try:
        conn_params = ConnectionParameters(
            host="rabbitmq",
            port=5672,
            credentials=PlainCredentials(
                username=config["connection"]["username"],
                password=config["connection"]["password"],
                # True would wipe the password after the first connect -> reconnects fail
                erase_on_connect=False,
            ),
            # on_message blocks up to ANALYSIS_TIMEOUT_S and pika can't send heartbeats meanwhile
            heartbeat=ANALYSIS_TIMEOUT_S + KILL_GRACE_S + 60,
            blocked_connection_timeout=300,
        )
        files_queue = config["queues"]["core_files_queue"]
        exchange = config["exchanges"]["main_exchange"]["name"]
    except (KeyError, TypeError) as e:
        logger.error("could not load configuration: %s", e)
        sys.exit(1)
        
    # One loop for connect + consume: any connection error reconnects instead of exiting
    while True:
        try:
            connection = BlockingConnection(conn_params)
            channel = connection.channel()
            # Same flags as the Rust side (both read config/rabbitmq.yaml), or declare fails
            channel.queue_declare(
                queue=files_queue["name"],
                durable=files_queue["durable"],
                auto_delete=files_queue["auto_delete"],
            )
            channel.queue_bind(exchange=exchange, queue=files_queue["name"],
                               routing_key=files_queue["name"])
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(queue=files_queue["name"], on_message_callback=on_message)
            logger.info("start consuming from RabbitMQ")
            channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Bye!")
            break
        except Exception as e:
            logger.error("RabbitMQ connection lost (%s), reconnecting in 5s ...", e)
            time.sleep(5)

if __name__ == "__main__":
    level = validate_log_level(os.environ.get("LOG_LEVEL", "info"))
    logging.basicConfig(stream=sys.stdout, level=level)

    parser = ArgumentParser(prog="Sandbox", description="RabbitMQ consumer")
    parser.add_argument("--samples-dir", default="./samples")
    parser.add_argument("--sandbox-lib", default="/sandbox/lib/app.js")
    parser.add_argument("--config-folder", default="/sandbox/config")

    args = parser.parse_args()
    logger.info("parsed flags: %s", args)
    run(
        samples_dir=args.samples_dir,
        sandbox_lib=args.sandbox_lib,
        config_folder=args.config_folder,
    )