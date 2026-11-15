# CYB-project
cyb class

**Packet Sniffer:**
- main.py : Entry point: CLI arguments, initializes components, ties the pipeline together
- capture.py : Network Interface Card (NIC) + Promiscuous Mode + BPF Filter Handling
-   NOTE: add offline (pcap) mode initially, and then develop it for active network sniffing.
- dissector.py : Parse raw bytes and layers into clean data objects
- reassembler.py : Stateful TCP stream tracking, sequence ordering, payload extraction
- logger.py : Console formatting, live alerts, and .pcap

<br>

**Test Scripts (Scapy-generated traffic):**
- icmp_test.py : Sends ICMP test packets to loopback (echo request, echo reply, destination unreachable, time exceeded, large payload)
- udp_test.py : Sends UDP test packets to loopback (basic, different ports, no payload, DNS port 53, large payload)
- NOTE: each test file has a run() function that main.py will call once the sniffer is listening/completed. Each test can also be run by itself. 

