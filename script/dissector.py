import socket
import struct
from dataclasses import dataclass, field
# Data classes and structures for dissecting network packets and packages needed

input_data: bytes = b"" # Raw input data for packet dissection
eth0: int = 0 # Ethernet interface index
src_ip: str = "" # Source IP address
dst_ip: str = "" # Destination IP address - should come 

@dataclass #based on ipv4 protocol
class Packet:
    raw_data: bytes = field(default=b"")
    src_ip: str = field(default="")
    dst_ip: str = field(default="")
    eth0: int = field(default=0)

    def __post_init__(self):
        self.raw_data = self.raw_data or input_data
        self.src_ip = self.src_ip or src_ip
        self.dst_ip = self.dst_ip or dst_ip
        self.eth0 = self.eth0 or eth0
@dataclass #based on ipv4 protocol
class IP_Headers:
    version: int = field(default=4)
    ihl: int = field(default=5)
    total_length: int = field(default=0)
    identification: int = field(default=0)
    flags: int = field(default=0)
    fragment_offset: int = field(default=0)
    ttl: int = field(default=64)
    protocol: int = field(default=0)
    header_checksum: int = field(default=0)
    src_ip: str = field(default="")
    dst_ip: str = field(default="")
#pick between TCP,UDP, ICMP, ARP
def Main():
    input_data = b"" # Example input data for packet dissection
    packet = Packet() 
    ip_headers = IP_Headers()