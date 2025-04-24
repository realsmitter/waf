FROM debian:bookworm-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3.11 \
    python3.11-venv \
    tcpdump \
    iproute2 \
    libpcap-dev \
    gcc \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set Python version explicitly to 3.11.2
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 && \
    update-alternatives --config python3

# Create and activate virtual environment
RUN python3 -m venv /app/venv

# Install Python dependencies in the virtual environment
COPY ./requirements.txt /app/requirements.txt
RUN /app/venv/bin/pip install --no-cache-dir --upgrade pip setuptools && \
    /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Create logs directory
RUN mkdir -p /app/log && mkdir -p /root/.mitmproxy && mkdir -p /app/src/templates

# Copy application code
COPY ./src /app/src

# Declare certificate directory as volume
VOLUME ["/root/.mitmproxy"]

# Expose ports for proxy server and web UI
EXPOSE 8080 80

# Container startup command
CMD ["/app/venv/bin/python", "/app/src/proxy_server.py"]

