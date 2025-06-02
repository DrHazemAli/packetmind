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
  • Statistics tracking and export functionality.
  • Real-time threat monitoring with alerts.
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
import hashlib
import csv
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple

# Third-party libraries:
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP, Raw
from openai import AzureOpenAI
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
flow_timestamps = {}  # Track last activity time for each flow
flow_lock = threading.Lock()

# Statistics tracking
stats = {
    'total_packets': 0,
    'total_flows': 0,
    'suspicious_flows': 0,
    'benign_flows': 0,
    'classification_errors': 0,
    'cache_hits': 0,
    'cache_misses': 0,
    'start_time': time.time(),
    'threats_detected': []
}
stats_lock = threading.Lock()

# A simple flag to shut down gracefully.
should_shutdown = threading.Event()

# Global executor (will be initialized later)
executor = None


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
    parser.add_argument(
        "--export-json", "-j", default="threats.json",
        help="Path to export detected threats as JSON.")
    parser.add_argument(
        "--export-csv", "-e", default="threats.csv",
        help="Path to export detected threats as CSV.")
    parser.add_argument(
        "--stats-interval", "-s", type=int, default=30,
        help="Interval in seconds to display statistics.")
    parser.add_argument(
        "--alert-threshold", "-a", type=int, default=5,
        help="Number of suspicious flows to trigger high-severity alert.")
    return parser.parse_args()


args = parse_args()

INTERFACE = args.interface
BPF_FILTER = args.bpf
CONFIDENCE_THRESHOLD = args.confidence_threshold
FLOW_MAX_BYTES = args.flow_max_bytes
FLOW_TIMEOUT = args.flow_timeout
WORKER_COUNT = args.workers
LOG_FILE_PATH = args.log_file
EXPORT_JSON_PATH = args.export_json
EXPORT_CSV_PATH = args.export_csv
STATS_INTERVAL = args.stats_interval
ALERT_THRESHOLD = args.alert_threshold

# Ensure user is root (only on Linux)
if sys.platform.startswith('linux') and os.geteuid() != 0:
    print("[!] ERROR: This script must be run as root (sudo) on Linux.")
    sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────────
# (3)— Logging Setup (Console + Rotating File)
# ────────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("dpi_inspector")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s", 
    datefmt="%Y-%m-%d %H:%M:%S")
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
    ai_client = AzureOpenAI(
        api_key=AZURE_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_ENDPOINT
    )
    logger.info("✅ Initialized Azure AI LLM client.")
except Exception as e:
    logger.error(f"[!] Failed to initialize Azure AI client: {e}")
    sys.exit(1)


# ────────────────────────────────────────────────────────────────────────────────
# (5)— Flow Management Functions
# ────────────────────────────────────────────────────────────────────────────────

def generate_flow_key(packet) -> Optional[str]:
    """Generate a canonical flow key from a packet."""
    try:
        if IP in packet and (TCP in packet or UDP in packet):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            if TCP in packet:
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
                protocol = "TCP"
            elif UDP in packet:
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport
                protocol = "UDP"
            else:
                return None
            
            # Create canonical key (smaller IP:port first)
            if (ip_src, port_src) < (ip_dst, port_dst):
                return f"{protocol}:{ip_src}:{port_src}-{ip_dst}:{port_dst}"
            else:
                return f"{protocol}:{ip_dst}:{port_dst}-{ip_src}:{port_src}"
        return None
    except Exception as e:
        logger.error(f"Error generating flow key: {e}")
        return None


def extract_payload_snippet(payload_data: bytes, max_length: int = 500) -> str:
    """Extract a readable snippet from payload data."""
    try:
        # Try to decode as UTF-8 first
        try:
            text = payload_data[:max_length].decode('utf-8', errors='ignore')
            if len(text.strip()) > 10:  # If we get meaningful text
                return text
        except:
            pass
        
        # Fallback to hex representation
        hex_data = payload_data[:max_length].hex()
        return f"HEX: {hex_data}"
    except Exception as e:
        return f"Error extracting payload: {e}"


def process_flow_buffer(flow_key: str, force: bool = False):
    """Process accumulated flow data and submit for classification."""
    with flow_lock:
        if flow_key not in flow_payloads:
            return
        
        payload_buffer = flow_payloads[flow_key]
        if len(payload_buffer) == 0:
            return
        
        # Check if we should process this flow
        should_process = (
            force or 
            len(payload_buffer) >= FLOW_MAX_BYTES or
            (flow_key in flow_timestamps and 
             time.time() - flow_timestamps[flow_key] > FLOW_TIMEOUT)
        )
        
        if not should_process:
            return
        
        # Copy data and clear buffer
        payload_copy = bytes(payload_buffer)
        del flow_payloads[flow_key]
        if flow_key in flow_timestamps:
            del flow_timestamps[flow_key]
    
    # Extract metadata
    parts = flow_key.split(':')
    protocol = parts[0]
    endpoints = parts[1].split('-')
    
    metadata = {
        'flow_key': flow_key,
        'protocol': protocol,
        'endpoints': endpoints,
        'payload_size': len(payload_copy),
        'timestamp': datetime.now().isoformat()
    }
    
    # Submit for async classification
    if executor and not should_shutdown.is_set():
        executor.submit(classify_and_log_flow, payload_copy, metadata)


def classify_and_log_flow(payload_data: bytes, metadata: dict):
    """Classify a flow's payload and log results."""
    try:
        payload_snippet = extract_payload_snippet(payload_data)
        classification = classify_payload_with_llm(payload_snippet, metadata)
        
        # Update statistics
        with stats_lock:
            if classification['is_suspicious'] and classification['confidence'] >= CONFIDENCE_THRESHOLD:
                stats['suspicious_flows'] += 1
                threat_info = {
                    'timestamp': metadata['timestamp'],
                    'flow_key': metadata['flow_key'],
                    'confidence': classification['confidence'],
                    'explanation': classification['explanation'],
                    'payload_size': metadata['payload_size']
                }
                stats['threats_detected'].append(threat_info)
                
                # Log high-confidence threats
                logger.warning(f"🚨 SUSPICIOUS FLOW DETECTED: {metadata['flow_key']} "
                             f"(confidence: {classification['confidence']:.2f}) - "
                             f"{classification['explanation']}")
                
                # Check for alert threshold
                if len(stats['threats_detected']) >= ALERT_THRESHOLD:
                    logger.critical(f"🔴 HIGH SEVERITY ALERT: {ALERT_THRESHOLD} or more threats detected!")
            else:
                stats['benign_flows'] += 1
                logger.info(f"✅ Benign flow: {metadata['flow_key']} "
                          f"(confidence: {classification['confidence']:.2f})")
        
        # Export threats periodically
        export_threats()
        
    except Exception as e:
        logger.error(f"Error in classify_and_log_flow: {e}")
        with stats_lock:
            stats['classification_errors'] += 1


# ────────────────────────────────────────────────────────────────────────────────
# (6)— LLM Classification Logic (with LRU Cache)
# ────────────────────────────────────────────────────────────────────────────────

def classify_payload_with_llm(payload_snippet: str, metadata: dict) -> dict:
    """Check cache → if missing, call Azure AI LLM and cache result."""
    
    # Create cache key from payload hash
    cache_key = hashlib.sha256(payload_snippet.encode()).hexdigest()[:16]
    
    with cache_lock:
        if cache_key in classification_cache:
            result = classification_cache[cache_key]
            classification_cache.move_to_end(cache_key)
            with stats_lock:
                stats['cache_hits'] += 1
            return result

    with stats_lock:
        stats['cache_misses'] += 1

    prompt = f"""
You are a network security expert. Given the following network-packet payload (text/hex),
analyze whether it represents *suspicious traffic* (e.g. C2-beacons, data exfiltration, malware callbacks, etc.).
Respond **ONLY** with a JSON object (no extra text) using these keys:
  • "is_suspicious": "yes" or "no"
  • "confidence": a number between 0.0 and 1.0
  • "explanation": a short rationale for your decision.

Flow metadata: {metadata['protocol']} {metadata['endpoints']} ({metadata['payload_size']} bytes)

PAYLOAD:
```
{payload_snippet}
```
"""
    try:
        response = ai_client.chat.completions.create(
            model=AZURE_DEPLOYMENT,
            messages=[
                {"role": "system", "content": "You are a network security analyzer."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.0,
        )
        raw = response.choices[0].message.content.strip()
        
        # Handle potential JSON parsing issues
        if raw.startswith('```json'):
            raw = raw[7:]
        if raw.endswith('```'):
            raw = raw[:-3]
        
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
        classification_cache[cache_key] = result
        if len(classification_cache) > cache_max_size:
            classification_cache.popitem(last=False)

    return result


# ────────────────────────────────────────────────────────────────────────────────
# (7)— Packet Processing
# ────────────────────────────────────────────────────────────────────────────────

def packet_callback(packet):
    """Process each captured packet."""
    try:
        with stats_lock:
            stats['total_packets'] += 1
        
        # Generate flow key
        flow_key = generate_flow_key(packet)
        if not flow_key:
            return
        
        # Extract payload
        payload = b''
        if Raw in packet:
            payload = bytes(packet[Raw])
        
        if len(payload) == 0:
            return  # Skip packets without payload
        
        # Update flow buffer
        with flow_lock:
            if flow_key not in flow_payloads:
                flow_payloads[flow_key] = bytearray()
                with stats_lock:
                    stats['total_flows'] += 1
            
            flow_payloads[flow_key].extend(payload)
            flow_timestamps[flow_key] = time.time()
        
        # Check if flow should be processed
        process_flow_buffer(flow_key)
        
    except Exception as e:
        logger.error(f"Error processing packet: {e}")
        logger.debug(traceback.format_exc())


# ────────────────────────────────────────────────────────────────────────────────
# (8)— Export and Statistics Functions
# ────────────────────────────────────────────────────────────────────────────────

def export_threats():
    """Export detected threats to JSON and CSV files."""
    try:
        with stats_lock:
            threats_copy = stats['threats_detected'].copy()
        
        if not threats_copy:
            return
        
        # Export to JSON
        with open(EXPORT_JSON_PATH, 'w') as f:
            json.dump({
                'export_time': datetime.now().isoformat(),
                'total_threats': len(threats_copy),
                'threats': threats_copy
            }, f, indent=2)
        
        # Export to CSV
        with open(EXPORT_CSV_PATH, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'flow_key', 'confidence', 'explanation', 'payload_size'])
            for threat in threats_copy:
                writer.writerow([
                    threat['timestamp'],
                    threat['flow_key'], 
                    threat['confidence'],
                    threat['explanation'],
                    threat['payload_size']
                ])
                
    except Exception as e:
        logger.error(f"Error exporting threats: {e}")


def print_statistics():
    """Print current statistics."""
    try:
        with stats_lock:
            runtime = time.time() - stats['start_time']
            print(f"\n{'='*60}")
            print(f"📊 PACKETMIND STATISTICS ({runtime:.1f}s runtime)")
            print(f"{'='*60}")
            print(f"Packets processed:     {stats['total_packets']:,}")
            print(f"Total flows:           {stats['total_flows']:,}")
            print(f"Suspicious flows:      {stats['suspicious_flows']:,}")
            print(f"Benign flows:          {stats['benign_flows']:,}")
            print(f"Classification errors: {stats['classification_errors']:,}")
            print(f"Cache hits/misses:     {stats['cache_hits']:,}/{stats['cache_misses']:,}")
            
            if stats['cache_hits'] + stats['cache_misses'] > 0:
                hit_rate = stats['cache_hits'] / (stats['cache_hits'] + stats['cache_misses']) * 100
                print(f"Cache hit rate:        {hit_rate:.1f}%")
            
            print(f"Threats detected:      {len(stats['threats_detected']):,}")
            print(f"{'='*60}\n")
            
    except Exception as e:
        logger.error(f"Error printing statistics: {e}")


def cleanup_expired_flows():
    """Clean up flows that have been idle for too long."""
    try:
        current_time = time.time()
        expired_flows = []
        
        with flow_lock:
            for flow_key, last_activity in flow_timestamps.items():
                if current_time - last_activity > FLOW_TIMEOUT:
                    expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            process_flow_buffer(flow_key, force=True)
            
    except Exception as e:
        logger.error(f"Error cleaning up expired flows: {e}")


def periodic_tasks():
    """Run periodic maintenance tasks."""
    while not should_shutdown.is_set():
        try:
            # Clean up expired flows
            cleanup_expired_flows()
            
            # Print statistics
            print_statistics()
            
            # Wait for next interval
            should_shutdown.wait(STATS_INTERVAL)
            
        except Exception as e:
            logger.error(f"Error in periodic tasks: {e}")


# ────────────────────────────────────────────────────────────────────────────────
# (9)— Signal Handlers and Main
# ────────────────────────────────────────────────────────────────────────────────

def shutdown_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info("🔴 Received shutdown signal. Cleaning up…")
    should_shutdown.set()
    
    # Process remaining flows
    try:
        with flow_lock:
            all_flows = list(flow_payloads.keys())
        for fk in all_flows:
            process_flow_buffer(fk, force=True)
    except Exception as e:
        logger.error(f"Error during flow cleanup: {e}")
    
    # Shutdown executor
    if executor:
        try:
            executor.shutdown(wait=True, timeout=10)
        except Exception as e:
            logger.error(f"Error shutting down executor: {e}")
    
    # Final export
    export_threats()
    print_statistics()
    
    logger.info("🟢 Shutdown complete.")
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


if __name__ == "__main__":
    # Initialize thread pool executor
    executor = ThreadPoolExecutor(max_workers=WORKER_COUNT)
    
    logger.info(f"🚀 Starting DPI Inspector on {INTERFACE} with filter: {BPF_FILTER}")
    logger.info(f"   • Flow max bytes: {FLOW_MAX_BYTES}, timeout: {FLOW_TIMEOUT}s")
    logger.info(f"   • Confidence threshold: {CONFIDENCE_THRESHOLD:.2f}")
    logger.info(f"   • Worker threads: {WORKER_COUNT}")
    logger.info(f"   • Rotating log file: {LOG_FILE_PATH}")
    logger.info(f"   • JSON export: {EXPORT_JSON_PATH}")
    logger.info(f"   • CSV export: {EXPORT_CSV_PATH}")
    logger.info(f"   • Statistics interval: {STATS_INTERVAL}s")
    logger.info(f"   • Alert threshold: {ALERT_THRESHOLD} threats")

    # Start periodic tasks in background thread
    stats_thread = threading.Thread(target=periodic_tasks, daemon=True)
    stats_thread.start()

    try:
        sniff(
            iface=INTERFACE,
            filter=BPF_FILTER,
            prn=packet_callback,
            store=False
        )
    except Exception as e:
        logger.error(f"[!] sniff() raised an exception: {e}")
        logger.debug(traceback.format_exc())
        shutdown_handler(None, None)
