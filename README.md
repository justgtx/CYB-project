# CYB-project
cyb class

Packet Sniffer:
- main.py : Entry point: CLI arguments, initializes components, ties the pipeline together
- capture.py : Network Interface Card (NIC) + Promiscuous Mode + BPF Filter Handling
- dissector.py : Parse raw bytes and layers into clean data objects
- reassembler.py : Stateful TCP stream tracking, sequence ordering, payload extraction
- logger.py : Console formatting, live alerts, and .pcap / database output

Packet Creation:

