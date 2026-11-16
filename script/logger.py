import json
import logging
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax import handler

class PacketLogger:
    # Handles the console summary output and saving of packet data to a JSON file.
    # Uses parsed packet produced by dissector.py
    
    def __init__(
        self,
        log_dir: str = "logs",
        json_filename: str = "packet_log.json",
        enable_console: bool = True,
        enable_file: bool = True
    ) -> None:
        self.enable_console = enable_console
        self.enable_file = enable_file
        self.packet_cnt = 0
        self.log_path = Path(log_dir) / json_filename
        if self.enable_file:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            
        self._sys_logger = logging.getLogger("PacketLogger")
        if not self._sys_logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
            
        handler.setFormatter(formatter)
        self._sys_logger.addHandler(handler)
        self._sys_logger.setLevel(logging.INFO)
        
    def info(self, message: str) -> None:
        # logs operational status messages like start/stop
        self._sys_logger.info(message)
    def error(self, message: str) -> None:
        # log capture or parsing errors.
        self._sys_logger.error(message)
    def log_packet(self, packet_data: Any) -> None:
        #prints a one-line summary of the packet to the console and saves the full packet data to a JSON file.
        self.packet_cnt += 1
        data = self._normalize(packet_data)
        
        if "logged_at" not in data:
            data["logged_at"] = datetime.now(timezone.utc).isoformat()
        if self.enable_console:
            print(self._format_summary(data), flush=True)
        if self.enable_file:
            self._write_jsonl(data)
            
    def _normalize(self, packet_data:Any) -> dict[str, Any]:
        #converts dataclass instances from dissector.py into dicts
        if is_dataclass(packet_data) and not isinstance(packet_data, type):
            return asdict(packet_data)
        if isinstance(packet_data, dict):
            return dict(packet_data)
        return {"raw_repr": repr(packet_data)}

    def _format_summary(self, data: dict[str, Any]) -> str:
        #builds concise one-line summary of the packet for console output
        ts = data.get("timestamp") or data.get("logged_at") or "N/A"
        proto = self._detect_protocol(data)
        src, dst = self._extract_endpoints(data)
        details = self._extract_details(data, proto)
        base = f"[{self.packet_count:04d}] {ts} | {proto:<5} | {src} -> {dst}"
        return f"{base} | {details}" if details else base
    
    def _extract_endpoints(self, data: dict[str, Any]) -> tuple[str, str]:
        #extracts source and destination addresses from the packet data
        ip_layer = data.get("ipv4") or data.get("ip") or data
        arp_layer = data.get("arp") or {}
        eth_layer = data.get("eth") or data.get("ethernet") or {}

        src_ip = ip_layer.get("src_ip") or arp_layer.get("src_ip") or "N/A"
        dst_ip = ip_layer.get("dst_ip") or arp_layer.get("dst_ip") or "N/A"

        transport = data.get("transport") or "N/A"
        src_port = data.get("src_port") or "N/A"
        dst_port = data.get("dst_port") or "N/A"
        
        if src_ip and dst_ip:
            src = f"{src_ip}:{src_port}" if src_port is not None else str(src_ip)
            dst = f"{dst_ip}:{dst_port}" if dst_port is not None else str(dst_ip)
            return src, dst
        
        src_mac = eth_layer.get("src_mac") or "N/A"
        dst_mac = eth_layer.get("dst_mac") or "N/A"
        return src_mac, dst_mac
    
    def _extract_details(self, data: dict[str, Any], proto: str) -> str:
        #extracts protocol-specific details for the summary line
        if data.get("tcp"):
            flags = data["tcp"].get("flags", "")
            seq = data["tcp"].get("seq", "")
            return f"Flags={flags} Seq={seq}".strip()
        if data.get("icmp"):
            icmp_type = data["icmp"].get("type", "")
            code = data["icmp"].get("code", "")
            return f"Type={icmp_type} Code={code}".strip()
        if data.get("arp"):
            op = data["arp"].get("op") or data["arp"].get("operation", "")
            return f"Op={op}"
        payload_len = data.get("payload_len") or data.get("length")
        return f"Len={payload_len}" if payload_len is not None else ""
    
    def _write_jsonl(self, data: dict[str, Any]) -> None:
        #appends the packet data as a JSON object to the log file
        with self.log_path.open("a", encoding="utf-8") as f:
            json.dump(data, f)
            f.write("\n")
            
    def _detect_protocol(self, data: dict[str, Any]) -> str:
        #detects the highest-level protocol present in the packet data
        if "tcp" in data:
            return "TCP"
        if "udp" in data:
            return "UDP"
        if "icmp" in data:
            return "ICMP"
        if "arp" in data:
            return "ARP"
        if "ipv4" in data or "ip" in data:
            return "IP"
        if "eth" in data or "ethernet" in data:
            return "ETH"
        return "UNKNOWN"