from scapy.all import *

# Read the pcap file
packets = rdpcap("E:\CapturedPackets1.pcap")

# Create separate TCP and UDP flows
tcp_packets = []
udp_packets = []

# Classify packets into TCP and UDP flows
for packet in packets:
    if TCP in packet:
        tcp_packets.append(packet)
    elif UDP in packet:
        udp_packets.append(packet)

# Display TCP flows
print("TCP Flows:")
for tcp_packet in tcp_packets:
    print(tcp_packet.summary())  # Example: Print the summary of each TCP packet

# Display UDP flows
print("UDP Flows:")
for udp_packet in udp_packets:
    print(udp_packet.summary())  # Example: Print the summary of each UDP packet
