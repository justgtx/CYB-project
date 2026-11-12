FROM ubuntu:24.4
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-scapy \
    && rm -rf /var/lib/apt/lists/*
