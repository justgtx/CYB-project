import struct
import time


class PcapFileWriter:
    # Writes raw Ethernet frames to a .pcap file (openable in Wireshark/tcpdump).
    #should also be able to view usin tshark
    # Named PcapFileWriter so it doesn't clash with Scapy's PcapWriter.

    def __init__(self, path: str) -> None:
        self._f = open(path, "wb")
        # 24-byte global header: magic, v2.4, tz=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
        self._f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, raw: bytes, timestamp: float | None = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        # 16-byte record header: seconds, microseconds, captured length, original length
        self._f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
        self._f.write(raw)
        self._f.flush()

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None