# Packet Sniffer

The packet sniffer is a software tool used to analyze and introspect network data. Packet traffic is observed through a physical connection and the required data frames are processed into a suitable representation for humans, with all the data decoded and the various headers and fields displayed, and its content analysed through one or more specifications.

## Features

### Format MAC addresses (data link layer)

The packet sniffer primarily deals with ethernet cables. The MAC addresses are found through unpacking ethernet frames and performing string operations to convert the bit-level data to a standard format hexadecimal string, thereby getting the source and destination addresses of traveling packets.

### Capturing traffic

All data packets that flow through a particular physical connection are caught and read by the software. Using the aforementioned feature, the data can be appropriately formatted for humans to view or stored in a database.

### Process IP data (network layer)

IP headers and packets are caught, analyzed, and unpacked into a string format for further processing.

### Process TCP, UDP, ICMP data (processing layer)

Similar to IP packets, datagrams from the processing layer of network architecture can be unpacked and viewed.

## Technologies

- Python3: Underlying driver code
- Sockets: Networking interface library
- Struct: Interpret bytes as packed binary data
- Textwrap: Data formatting and processing
- Scapy: Packet forging
