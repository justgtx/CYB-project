import sys
import logging
from typing import Callable, Optional
from scapy.all import sniff, get_if_list, conf
from scapy.packet import Packet

logging.basicConfig(
    level = logging.INFO,
    format="%(asctime)s [%l(evelnames)s %(message)s]",
    datefmt="%H:%M:%S"
)

logger = logging.getLogger("PacketCapture")

class PacketSniffer:
    # Will handle NIC Selection, Promiscuous Mode, and BPF Filtering Utilizing Scapy
    
    def __init__(
        self,
        interface:Optional[str] = None,
        bpf_filter: str = "",
        promiscuous: bool = True
    ):
        self.interface = interface or str(conf.iface)
        self.bpfilter = bpf_filter
        self.promiscuous = promiscuous
        
        self._validate_interface()
    def _validate_interface(self) -> None:
        #basically ensures that the required NIC is on the system
        available = get_if_list()
        if self.interface not in available:
            raise ValueError(
                f"Interface '{self.interface}' not found. "
                f"Available interfaces: {', '.join(available)}"
            )
    
    @staticmethod
    def list_interfaces() -> list[str]:
        #Returns a list of all available network interfaces
        return get_if_list()
