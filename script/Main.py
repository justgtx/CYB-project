#scapy3 imports
from scapy.all import AsyncSniffer
import threading
import sys
import time 
import socket
import struct
import signal 
from capture import *
from dissector import *
from logger import PacketLogger
from tcp_test import *
from udp_test import *

try:
    from dissector import dissect_packet
except ImportError:
    dissect_packet = None
    
def get_loopback_interface() -> str:
    #Returns the name of the loopback interface based on the OS.
    if conf.loopback_name:
        return conf.loopback_name
    return "lo"

def _fallback_extract(pkt) -> dict | None:
    if not pkt.haslayer("IP"):
        return None
    
    raw_payload = (
        pkt["Raw"].load.decode(errors="replace")
        if pkt.haslayer("Raw")
        else None
    )
    
    data = {
        "src_ip": pkt["IP"].src,
        "dst_ip": pkt["IP"].dst,
        "protocol": pkt["IP"].proto,
        "payload_len": len(pkt["IP"].payload),
        "payload": raw_payload[:60],
    }
    
    if pkt.haslayer("TCP"):
        data["protocol"] = "TCP"
        data["tcp"] = {
            "src_port": pkt["TCP"].sport,
            "dst_port": pkt["TCP"].dport,
            "flags": str(pkt["TCP"].flags),
            "seq": pkt["TCP"].seq,
        }
    elif pkt.haslayer("UDP"):
        data["protocol"] = "UDP"
        data["udp"] = {
            "src_port": pkt["UDP"].sport,
            "dst_port": pkt["UDP"].dport,
        }

    return data

def process_packet(pkt, logger: PacketLogger) -> None:
    #Processes a single packet, logs it, and prints a summary.
    if dissect_packet:
        data = dissect_packet(pkt)
    else:
        data = _fallback_extract(pkt)
    
    if data:
        logger.log_packet(data)
        print(logger.format_summary(data))
        
def main() -> None:#scapy3 imports
    from scapy.all import AsyncSniffer, conf
conf.use_pcap = True   # use libpcap (from tcpdump): it drops the duplicate outgoing copy on loopback
import argparse
import time
import sys
from logger import PacketLogger
import tcp_test
import udp_test
import icmp_test

try:
    from dissector import dissect_packet
except ImportError:
    dissect_packet = None
    
def get_loopback_interface() -> str:
    #Returns the name of the loopback interface based on the OS.
    if conf.loopback_name:
        return conf.loopback_name
    return "lo"

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Packet sniffer")
    ap.add_argument("-o", "--out-dir", default="logs",
                    help="folder for the JSON log and .pcap (default: logs)")
    ap.add_argument("-i", "--iface", default=None,
                    help="interface to sniff on (default: loopback)")
    return ap.parse_args()

def _fallback_extract(pkt) -> dict | None:
    if not pkt.haslayer("IP"):
        return None
    
    raw_payload = (
        pkt["Raw"].load.decode(errors="replace")
        if pkt.haslayer("Raw")
        else None
    )
    
    data = {
        "src_ip": pkt["IP"].src,
        "dst_ip": pkt["IP"].dst,
        "protocol": pkt["IP"].proto,
        "payload_len": len(pkt["IP"].payload),
        "payload": raw_payload[:60] if raw_payload else None,
    }
    
    if pkt.haslayer("TCP"):
        data["protocol"] = "TCP"
        data["tcp"] = {
            "src_port": pkt["TCP"].sport,
            "dst_port": pkt["TCP"].dport,
            "flags": str(pkt["TCP"].flags),
            "seq": pkt["TCP"].seq,
        }
    elif pkt.haslayer("UDP"):
        data["protocol"] = "UDP"
        data["udp"] = {
            "src_port": pkt["UDP"].sport,
            "dst_port": pkt["UDP"].dport,
        }
    elif pkt.haslayer("ICMP"):
        data["protocol"] = "ICMP"
        data["icmp"] = {
            "type": pkt["ICMP"].type,
            "code": pkt["ICMP"].code,
        }

    return data

def process_packet(pkt, logger: PacketLogger) -> None:
    #Processes a single packet and logs it (log_packet prints the summary itself).
    if dissect_packet:
        data = dissect_packet(pkt)
    else:
        data = _fallback_extract(pkt)
    
    if data:
        logger.log_packet(data, raw=bytes(pkt))   # raw bytes go to the .pcap
        
def main() -> None:
    args = parse_args()
    iface = args.iface or get_loopback_interface()
    logger = PacketLogger(log_dir=args.out_dir,
                          json_filename="test_capture.jsonl",
                          pcap_filename="test_capture.pcap")

    # Capture only the loopback test ports (and ICMP) to avoid unrelated local traffic
    bpf_filter = "ip host 127.0.0.1 and (port 9999 or port 8888 or port 53 or icmp)"

    logger.info(f"Starting background sniffer on '{iface}'...")
    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=lambda pkt: process_packet(pkt, logger),
        store=False,
    )

    sniffer.start()
    time.sleep(1.0)  # Give the sniffer time to bind before sending traffic

    try:
        logger.info("Sending TCP test packets...")
        tcp_test.run()

        logger.info("Sending UDP test packets...")
        udp_test.run()

        logger.info("Sending ICMP test packets...")
        icmp_test.run()

        time.sleep(1.0)  # Allow final packets to finish processing
    finally:
        logger.info("Stopping sniffer...")
        if sniffer.running:
            sniffer.stop()
        else:
            logger.info("Sniffer was not running.")
        logger.close()
        logger.info(f"Done. Total packets logged: {logger.packet_cnt}")
        logger.info(f"Files in: {args.out_dir}")


if __name__ == "__main__":
    main()
    iface = get_loopback_interface()
    logger = PacketLogger(log_dir="logs", json_filename="test_capture.jsonl")

    # Capture only the loopback test ports to avoid unrelated local traffic
    bpf_filter = "ip host 127.0.0.1 and (port 9999 or port 8888 or port 53)"

    logger.info(f"Starting background sniffer on '{iface}'...")
    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=lambda pkt: process_packet(pkt, logger),
        store=False,
    )

    sniffer.start()
    time.sleep(1.0)  # Give the sniffer time to bind before sending traffic

    try:
        logger.info("Sending TCP test packets...")
        subprocess.run([sys.executable, "script/tcp_test.py"], check=True)

        logger.info("Sending UDP test packets...")
        subprocess.run([sys.executable, "script/udp_test.py"], check=True)

        time.sleep(1.0)  # Allow final packets to finish processing
    finally:
        logger.info("Stopping sniffer...")
        if sniffer.running:
            sniffer.stop()
        else:
            logger.info("Sniffer was not running.")
        logger.info(f"Done. Total packets logged: {logger.packet_cnt}")


if __name__ == "__main__":
    main()