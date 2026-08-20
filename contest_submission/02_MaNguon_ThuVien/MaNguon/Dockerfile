# S7Pwn Docker Container
# Build: docker build -t s7pwn .
# Run CLI: docker run -it --net=host s7pwn
# Run Web: docker run -it --net=host -p 5000:5000 s7pwn webgui 0.0.0.0

FROM python:3.11-slim

LABEL maintainer="S7Pwn Security Research"
LABEL description="Siemens S7 PLC Security Testing Tool"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY s7pwn/ ./s7pwn/
COPY start_webgui.py .
COPY README.md FEATURES.md QUICK_START.md ./

# Create reports directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=s7pwn.web_gui

# Install s7pwn package
RUN pip install -e .

# Expose web GUI port
EXPOSE 5000

# Default command: show help
CMD ["python", "-m", "s7pwn.cli"]
