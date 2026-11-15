import sys
import logging
from typing import Callable, Optional
from scapy.all import sniff, get_if_list, conf
from scapy.packet import Packet
import os

logging.basicConfig(
    level = logging.INFO,
    format="%(asctime)s [%(levelname)s %(message)s]",
    datefmt="%H:%M:%S"
)

logger = logging.getLogger("PacketCapture")

class PacketSniffer:
    # Will handle NIC Selection, Promiscuous Mode, and BPF Filtering Utilizing Scapy
    
    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: str = "",
        promiscuous: bool = True
    ):
        self.interface = interface or str(conf.iface)
        self.bpfilter = bpf_filter
        self.promiscuous = promiscuous
        self.pcap_file = pcap_file
        
        if self.pcap_file:
            if not os.path.exists(self.pcap_file):
                raise FileNotFoundError(f"PCAP file '{self.pcap_file}' does not exist.")
        else:
            self._validate_interface()
    def _validate_interface(self) -> None:
        #basically ensures that the required NIC is on the system
        available = get_if_list()
        if self.interface not in available:
            raise ValueError(
                f"Interface '{self.interface}' not found. "
                f"Available interfaces: {', '.join(available)}"
            )
    
    def start(self, packet_callback: Callable[[Packet],None],packet_count:int=0) -> None:
        if self.pcap_file:
            #offline mode, no need to put NIC in promiscuous mode and scan.
            sniff(
                offline = self.pcap_file,
                filter = self.bpfilter if self.bpfilter else None,
                prn = packet_callback,
                count = packet_count,
                store = False
            )
        else:
            #Live mode, put NIC in promiscuous mode and scan.
            sniff(
                iface = self.interface,
                filter = self.bpfilter if self.bpfilter else None,
                prn = packet_callback,
                count = packet_count,
                store = False,
                promisc=self.promiscuous
            )
            
if __name__ == "__main__":
    # Quick standalone verification when running `python capture.py` directly
    from scapy.all import Ether, IP, TCP, wrpcap

    demo_pcap = "demo_test.pcap"
    wrpcap(demo_pcap, [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)])

    try:
        sniffer = PacketSniffer(pcap_file=demo_pcap, bpf_filter="tcp")
        sniffer.start(packet_callback=lambda pkt: logger.info(f"Packet received -> {pkt.summary()}"))
    finally:
        if os.path.exists(demo_pcap):
            os.remove(demo_pcap)
