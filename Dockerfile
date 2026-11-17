FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-scapy \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /packet-sniffer
COPY script/ /packet-sniffer/script/
RUN chmod 755 /packet-sniffer/*

RUN chmod +x /packet-sniffer/script/Main.py
CMD ["python3", "script/Main.py"]
