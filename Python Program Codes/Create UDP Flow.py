from scapy.all import *

# Create the UDP flow packets
src_ip = "192.168.0.1"  # Source IP address
dst_ip = "192.168.0.2"  # Destination IP address
src_port = 12345  # Source port number
dst_port = 54321  # Destination port number

# Craft a UDP packet
udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Hello, Server!"

# Send the UDP packet
send(udp_packet)
