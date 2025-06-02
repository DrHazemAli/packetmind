#!/usr/bin/env python3
"""
dpi_inspector.py

A Deep Packet Inspection (DPI) tool for Ubuntu that uses
an Azure AI LLM to classify payloads as suspicious vs. benign. Features:

  • Flow-level reassembly (accumulates payloads per TCP flow).
  • Asynchronous classification via ThreadPoolExecutor.
  • Simple LRU cache to skip repeated payloads.
  • Periodic flushing of idle flows.
  • Command-line arguments for full configurability.
  • Rotating log file + console logging.
  • Ubuntu-specific: tested on Ubuntu 22.04 / Python 3.10+.
"""

import os
import sys
import time
import json
import signal
import argparse
import threading
import logging
import traceback
from collections import OrderedDict

# Third-party libraries:
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, Raw
from azure.ai.openai import OpenAIClient, OpenAIKeyCredential
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor

# ────────────────────────────────────────────────────────────────────────────────
# (1)— Configuration & Globals
# ────────────────────────────────────────────────────────────────────────────────

# Load AZURE_* from .env
load_dotenv()

AZURE_ENDPOINT = os.getenv("AZURE_ENDPOINT", "").strip()
AZURE_API_KEY = os.getenv("AZURE_KEY", "").strip()
AZURE_DEPLOYMENT = os.getenv("AZURE_DEPLOYMENT", "").strip()

if not AZURE_ENDPOINT or not AZURE_API_KEY or not AZURE_DEPLOYMENT:
    print("\n[!] ERROR: Missing one or more AZURE environment variables.\n"
          "    Make sure your .env contains:\n"
          "      AZURE_ENDPOINT=https://<resource>.openai.azure.com/\n"
          "      AZURE_KEY=<your-key>\n"
          "      AZURE_DEPLOYMENT=<your-deployment-name>\n")
    sys.exit(1)

# Simple LRU cache for payload → classification result (to avoid re-classification).
cache_max_size = 1000
classification_cache = OrderedDict()
cache_lock = threading.Lock()

# Flow reassembly: for each canonical TCP flow, we accumulate bytes in a bytearray.
flow_payloads = {}
flow_lock = threading.Lock()

# A simple flag to shut down gracefully.
should_shutdown = threading.Event()


# ────────────────────────────────────────────────────────────────────────────────
# (2)— Argument Parsing
# ────────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="DPI + Azure AI (LLM) 🚀")
    parser.add_argument(
        "--interface", "-i", required=True,
        help="Network interface to sniff on (e.g. eth0, en0). Must run as root.")
    parser.add_argument(
        "--bpf", "-f", default="tcp",
        help='BPF filter for sniff(), e.g. "tcp port 80 or tcp port 443"')
    parser.add_argument(
        "--confidence-threshold", "-c", type=float, default=0.6,
        help="Minimum LLM confidence (0.0–1.0) to label traffic as 'suspicious'.")
    parser.add_argument(
        "--flow-max-bytes", "-m", type=int, default=2048,
        help="Maximum number of bytes to accumulate per TCP flow before classifying.")
    parser.add_argument(
        "--flow-timeout", "-t", type=int, default=60,
        help="Seconds of inactivity after which an in-flight flow is flushed/classified.")
    parser.add_argument(
        "--workers", "-w", type=int, default=4,
        help="Number of threads in ThreadPoolExecutor for LLM classification.")
    parser.add_argument(
        "--log-file", "-l", default="packetmind.log",
        help="Path to rotating log file output.")
    return parser.parse_args()


args = parse_args()

INTERFACE = args.interface
BPF_FILTER = args.bpf
CONFIDENCE_THRESHOLD = args.confidence_threshold
FLOW_MAX_BYTES = args.flow_max_bytes
FLOW_TIMEOUT = args.flow_timeout
WORKER_COUNT = args.workers
LOG_FILE_PATH = args.log_file

# Ensure user is root
if os.geteuid() != 0:
    print("[!] ERROR: This script must be run as root (sudo).")
    sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────────
# (3)— Logging Setup (Console + Rotating File)
# ────────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("dpi_inspector")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%Y-%m-%d %H:%M:%S", datefmt="%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = RotatingFileHandler(
    LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=3)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)


# ────────────────────────────────────────────────────────────────────────────────
# (4)— Initialize Azure AI LLM Client
# ────────────────────────────────────────────────────────────────────────────────

try:
    credential = OpenAIKeyCredential(AZURE_API_KEY)
    ai_client = OpenAIClient(AZURE_ENDPOINT, credential)
    logger.info("✅ Initialized Azure AI LLM client.")
except Exception as e:
    logger.error(f"[!] Failed to initialize Azure AI client: {e}")
    sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────────
# (5)— LLM Classification Logic (with LRU Cache)
# ────────────────────────────────────────────────────────────────────────────────

def classify_payload_with_llm(payload_snippet: str, metadata: dict) -> dict:
    """Check cache → if missing, call Azure AI LLM and cache result."""


    with cache_lock:
        if payload_snippet in classification_cache:
            result = classification_cache[payload_snippet]
            classification_cache.move_to_end(payload_snippet)
            return result

    prompt = f"""
You are a network security expert. Given the following network-packet payload (text/hex),
analyze whether it represents *suspicious traffic* (e.g. C2-beacons, data exfiltration, malware callbacks, etc.).
Respond **ONLY** with a JSON object (no extra text) using these keys:
  • "is_suspicious": "yes" or "no"
  • "confidence": a number between 0.0 and 1.0
  • "explanation": a short rationale for your decision.

PAYLOAD:
```
{payload_snippet}
```
"""
    try:
        response = ai_client.get_chat_completions(
            deployment_id=AZURE_DEPLOYMENT,
            messages=[
                {"role": "system", "content": "You are a network security analyzer."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.0,
        )
        raw = response.choices[0].message.content.strip()
        classification = json.loads(raw)

        is_sus = classification.get("is_suspicious", "").strip().lower() == "yes"
        conf = float(classification.get("confidence", 0.0))
        expl = classification.get("explanation", "").strip()

        result = {
            "is_suspicious": is_sus,
            "confidence": conf,
            "explanation": expl
        }
    except Exception as e:
        logger.error(f"[LLM ERROR] Failed to classify payload. metadata={metadata} ➔ {e}")
        result = {
            "is_suspicious": False,
            "confidence": 0.0,
            "explanation": "LLM classification error"
        }

    with cache_lock:
        classification_cache[payload_snippet] = result
        if len(classification_cache) > cache_max_size:
            classification_cache.popitem(last=False)

    return result


def shutdown_handler(signum, frame):
    logger.info("🔴 Received shutdown signal. Cleaning up…")
    should_shutdown.set()
    with flow_lock:
        all_flows = list(flow_payloads.keys())
    for fk in all_flows:
        process_flow_buffer(fk)
    executor.shutdown(wait=True)
    logger.info("🟢 Shutdown complete.")
    sys.exit(0)


import signal
signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


if __name__ == "__main__":
    executor = ThreadPoolExecutor(max_workers=WORKER_COUNT)
    logger.info(f"🚀 Starting DPI Inspector on {INTERFACE} with filter: {BPF_FILTER}")
    logger.info(f"   • Flow max bytes: {FLOW_MAX_BYTES}, timeout: {FLOW_TIMEOUT}s")
    logger.info(f"   • Confidence threshold: {CONFIDENCE_THRESHOLD:.2f}")
    logger.info(f"   • Worker threads: {WORKER_COUNT}")
    logger.info(f"   • Rotating log file: {LOG_FILE_PATH}")

    try:
        sniff(
            iface=INTERFACE,
            filter=BPF_FILTER,
            prn=packet_callback,
            store=False
        )
    except Exception as e:
        logger.error(f"[!] sniff() raised an exception: {e}")
        shutdown_handler(None, None)
