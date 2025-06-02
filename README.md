# PacketMind - AI-Powered Deep Packet Inspection Tool 🚀

PacketMind is a cutting-edge Deep Packet Inspection (DPI) tool that leverages Azure OpenAI to intelligently classify network traffic as suspicious or benign. It provides real-time threat detection, flow reassembly, and comprehensive analytics.

![PacketMind Logo](https://github.com/drhazemali/packetmind/blob/main/banner.png)

## ✨ Features

### Core Functionality
- **AI-Powered Classification**: Uses Azure OpenAI LLM to analyze packet payloads
- **Flow-Level Reassembly**: Accumulates TCP/UDP payloads per flow for better context
- **Real-Time Processing**: Asynchronous classification with ThreadPoolExecutor
- **Intelligent Caching**: LRU cache to avoid re-analyzing identical payloads

### Monitoring & Analytics
- **Real-Time Statistics**: Live display of processing metrics
- **Threat Export**: Automatic export to JSON and CSV formats
- **Alert System**: Configurable thresholds for high-severity alerts
- **Performance Metrics**: Cache hit rates, processing speeds, error tracking

### Advanced Features
- **Flow Timeout Management**: Automatic cleanup of idle flows
- **Rotating Logs**: Configurable log file rotation
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Configurable Filters**: Custom BPF filters for targeted monitoring
- **Graceful Shutdown**: Proper cleanup on exit signals

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet capture)
- Azure OpenAI service account

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Configure Azure OpenAI
1. Copy the example environment file:
   ```bash
   cp env_example.txt .env
   ```

2. Edit `.env` with your Azure OpenAI credentials:
   ```bash
   AZURE_ENDPOINT=https://your-resource-name.openai.azure.com/
   AZURE_KEY=your-api-key-here
   AZURE_DEPLOYMENT=your-deployment-name
   ```

## 🚀 Usage

### Basic Usage
```bash
# Linux/macOS (requires sudo)
sudo python3 dpi_inspector.py --interface eth0

# Windows (run as Administrator)
python dpi_inspector.py --interface "Ethernet"
```

### Advanced Configuration
```bash
sudo python3 dpi_inspector.py \
    --interface eth0 \
    --bpf "tcp port 443 or tcp port 80" \
    --confidence-threshold 0.7 \
    --flow-max-bytes 4096 \
    --flow-timeout 120 \
    --workers 8 \
    --stats-interval 60 \
    --alert-threshold 10 \
    --export-json threats_$(date +%Y%m%d).json \
    --export-csv threats_$(date +%Y%m%d).csv
```

## 📊 Command Line Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--interface` | `-i` | **Required** | Network interface (eth0, en0, etc.) |
| `--bpf` | `-f` | `tcp` | BPF filter for packet capture |
| `--confidence-threshold` | `-c` | `0.6` | Minimum AI confidence for suspicious classification |
| `--flow-max-bytes` | `-m` | `2048` | Max bytes per flow before classification |
| `--flow-timeout` | `-t` | `60` | Flow inactivity timeout (seconds) |
| `--workers` | `-w` | `4` | Number of classification worker threads |
| `--log-file` | `-l` | `packetmind.log` | Log file path |
| `--export-json` | `-j` | `threats.json` | JSON export file path |
| `--export-csv` | `-e` | `threats.csv` | CSV export file path |
| `--stats-interval` | `-s` | `30` | Statistics display interval (seconds) |
| `--alert-threshold` | `-a` | `5` | Threat count for high-severity alerts |

## 📈 Output and Exports

### Real-Time Console Output
```
2024-01-15 10:30:25 - dpi_inspector - INFO - 🚀 Starting DPI Inspector on eth0 with filter: tcp
2024-01-15 10:30:26 - dpi_inspector - WARNING - 🚨 SUSPICIOUS FLOW DETECTED: TCP:192.168.1.100:443-10.0.0.5:52341 (confidence: 0.85) - Potential C2 beacon pattern detected
2024-01-15 10:30:56 - dpi_inspector - INFO - ✅ Benign flow: TCP:192.168.1.100:80-10.0.0.5:52342 (confidence: 0.92)

============================================================
📊 PACKETMIND STATISTICS (30.0s runtime)
============================================================
Packets processed:     1,245
Total flows:           45
Suspicious flows:      3
Benign flows:          42
Classification errors: 0
Cache hits/misses:     128/45
Cache hit rate:        74.0%
Threats detected:      3
============================================================
```

### JSON Export Format
```json
{
  "export_time": "2024-01-15T10:31:00.123456",
  "total_threats": 3,
  "threats": [
    {
      "timestamp": "2024-01-15T10:30:26.789012",
      "flow_key": "TCP:192.168.1.100:443-10.0.0.5:52341",
      "confidence": 0.85,
      "explanation": "Potential C2 beacon pattern detected",
      "payload_size": 1024
    }
  ]
}
```

### CSV Export Format
```csv
timestamp,flow_key,confidence,explanation,payload_size
2024-01-15T10:30:26.789012,TCP:192.168.1.100:443-10.0.0.5:52341,0.85,Potential C2 beacon pattern detected,1024
```

## 🔍 BPF Filter Examples

| Use Case | BPF Filter |
|----------|------------|
| HTTP/HTTPS only | `tcp port 80 or tcp port 443` |
| DNS traffic | `udp port 53` |
| SSH connections | `tcp port 22` |
| Email protocols | `tcp port 25 or tcp port 110 or tcp port 143 or tcp port 993 or tcp port 995` |
| Non-standard ports | `tcp portrange 8000-9000` |
| Specific host | `host 192.168.1.100` |
| Outbound only | `src net 192.168.0.0/16` |

## 🛡️ Security Considerations

- **Run with minimal privileges**: Only packet capture requires elevated privileges
- **Secure API keys**: Protect your Azure OpenAI credentials
- **Monitor resources**: AI classification can be resource-intensive
- **Data privacy**: Be aware of what traffic you're analyzing
- **Compliance**: Ensure monitoring complies with local regulations

## 🔧 Troubleshooting

### Common Issues

**Permission denied when capturing packets:**
```bash
# Linux
sudo python3 dpi_inspector.py --interface eth0

# Add user to group (alternative)
sudo usermod -a -G wireshark $USER
```

**Interface not found:**
```bash
# List available interfaces
ip link show                    # Linux
ifconfig                       # macOS
netsh interface show interface # Windows
```

**Azure OpenAI connection errors:**
- Verify your `.env` file credentials
- Check network connectivity to Azure
- Ensure your deployment is active
- Verify API key permissions

**High memory usage:**
- Reduce `--flow-max-bytes`
- Decrease `--workers` count
- Use more specific BPF filters
- Increase `--flow-timeout` for faster cleanup

## 📝 Log Files

PacketMind creates rotating log files with the following information:
- All detected threats with full details
- Processing statistics and performance metrics
- Error messages and debugging information
- Configuration and startup information

Log files rotate when they reach 5MB, keeping 3 backup files.

## 🤝 Contributing

Contributions are welcome! Please consider:
- Bug reports and feature requests
- Performance optimizations
- Additional AI model integrations
- Extended export formats
- Enhanced threat detection patterns

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

PacketMind is intended for legitimate network security monitoring purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Always obtain proper authorization before monitoring network traffic.
