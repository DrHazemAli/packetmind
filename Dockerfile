FROM python:3.10-slim

# Install system dependencies required for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip and install wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements first for better cache usage
COPY requirements.txt .

# Install Python dependencies with verbose output for debugging
RUN pip install --no-cache-dir --verbose -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user for better security
RUN useradd -m -u 1000 packetmind && \
    chown -R packetmind:packetmind /app

# Switch to non-root user
USER packetmind

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose any ports if needed (none for this CLI tool)
# EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import scapy; print('OK')" || exit 1

# Default command
ENTRYPOINT ["python", "dpi_inspector.py"]
CMD ["--help"] 