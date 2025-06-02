# PacketMind

PacketMind is an advanced Deep Packet Inspection (DPI) tool for Ubuntu that leverages an Azure AI LLM to identify suspicious network traffic in real time. It performs flow-level reassembly, caches results to minimize redundant AI calls, and processes classification concurrently using worker threads. PacketMind is designed for security analysts and network administrators who want to augment traditional rule-based DPI with AI-driven anomaly detection.

![PacketMind Logo](https://github.com/drhazemali/packetmind/blob/main/banner.png)

## Features

- **Flow-level Reassembly**: Accumulates TCP payloads per flow for more accurate classification.
- **AI-driven Classification**: Sends payload snippets to an Azure-hosted LLM to determine if traffic is suspicious.
- **LRU Cache**: Caches payload results to reduce duplicate AI calls and save cost.
- **Concurrent Processing**: Uses a thread pool to classify multiple flows in parallel.
- **Idle Flow Timeout**: Periodically flushes flows that have been idle for a configurable duration.
- **Configurable**: Adjust interface, BPF filter, timeouts, and thresholds via command-line arguments.
- **Ubuntu Compatibility**: Tested on Ubuntu 22.04 LTS and newer (Python 3.10+).
- **Rotating Logs**: Logs to both console and rotating log file for long-term retention.

## Repository Structure

```
packetmind/
├── dpi_inspector.py      # Main DPI script
├── requirements.txt      # Python dependencies
├── .env.example          # Example environment variables file
├── README.md             # This file
├── LICENSE               # MIT License
└── .gitignore            # Standard Git ignore patterns
```

## Prerequisites

1. **Ubuntu 22.04 LTS (or newer)** with root privileges to capture packets.
2. **Python 3.10+** installed.
3. **Azure AI (OpenAI-compatible) resource** with a deployed LLM (e.g., `gpt-35-turbo`).
4. **Network interface** in promiscuous mode if deploying on a dedicated capture device or using a TAP.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/drhazemali/packetmind.git
   cd packetmind
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install Python dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and fill in your Azure AI credentials:
   ```bash
   cp .env.example .env
   ```
   Edit `.env`:
   ```text
   AZURE_ENDPOINT=https://<your-resource>.openai.azure.com/
   AZURE_KEY=<your-azure-api-key>
   AZURE_DEPLOYMENT=<your-deployment-name>
   ```

## Usage

Run PacketMind as root to capture and inspect live traffic:

```bash
sudo python3 dpi_inspector.py \
  --interface <network-interface> \
  --bpf "tcp port 80 or tcp port 443" \
  --confidence-threshold 0.6 \
  --flow-max-bytes 2048 \
  --flow-timeout 60 \
  --workers 4 \
  --log-file packetmind.log
```

- `--interface`: Network interface to sniff on (e.g., `eth0`, `ens33`, `wlp2s0`).
- `--bpf`: BPF filter to limit captured traffic (e.g., `"tcp port 80 or tcp port 443"`).
- `--confidence-threshold`: Minimum AI confidence (0.0–1.0) to flag traffic as suspicious.
- `--flow-max-bytes`: Bytes to accumulate per flow before forcing classification.
- `--flow-timeout`: Seconds of inactivity before flushing a flow.
- `--workers`: Number of threads to use for concurrent AI classification.
- `--log-file`: Path to the rotating log file.

Example:
```bash
sudo python3 dpi_inspector.py -i eth0 -f "tcp port 80 or tcp port 443" -c 0.6 -m 2048 -t 60 -w 4 -l packetmind.log
```

## Configuration Options

- **FLOW_MAX_BYTES**: Defaults to 2048. Adjust if you want larger flow context before classification.
- **FLOW_TIMEOUT**: Defaults to 60 seconds. Flows idle beyond this will be classified and removed.
- **CONFIDENCE_THRESHOLD**: Defaults to 0.6. Lower to flag more flows as suspicious; raise to reduce false positives.
- **WORKERS**: Number of concurrent threads for AI classification. Increase for higher throughput (requires more CPU).
- **BPF Filter**: Customize BPF to inspect other protocols (e.g., `"udp port 53"` for DNS).

## Alerting & Integration

Currently, PacketMind logs suspicious flows to console and `packetmind.log`. You can extend `classify_and_alert()` in `dpi_inspector.py` to integrate with:

- **Email or SMS notifications** via SMTP or third-party APIs.
- **SIEM platforms** (Splunk, Elastic, QRadar) by writing JSON alerts to a watched endpoint or file.
- **Firewall automation** (e.g., using iptables or Azure NSG) to block suspicious IPs.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push to branch: `git push origin feature/your-feature`
5. Submit a Pull Request.

Please follow the existing code style and update tests (if any) accordingly.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
