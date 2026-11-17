import socket
import struct
from dataclasses import dataclass
from typing import Optional

@dataclass
class IPv4Header:
    version: int #4 bits
    header_len: int     #4 bits       # header length in bytes
    type_of_service:int #8 bits
    total_length: int #16 bits
    identification: int #16 bits
    flags: int #3
    fragment_offset: int #13 bits
    ttl: int   #8 bits
    protocol: int    #8bits   # 1=ICMP, 6=TCP, 17=UDP
    checksum: int   #16 
    src_ip: str #32 bits
    dst_ip: str #32 bits

@dataclass# handle for the optional part
class Packet:
    raw_data: bytes
    ip: Optional[IPv4Header] = None   # None for non-IP frames like ARP

def parse_ipv4(data: bytes) -> IPv4Header:
    if len(data) < 20:
        raise ValueError("truncated IPv4 header")
    (ver_ihl, tos, total, ident, flags_frag,
     ttl, proto, csum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:20])
    return IPv4Header(ver_ihl >> 4, (ver_ihl & 0x0F) * 4, tos, total, ident,
                      flags_frag >> 13, (flags_frag & 0x1FFF) * 8,
                      ttl, proto, csum,
                      socket.inet_ntoa(src), socket.inet_ntoa(dst))