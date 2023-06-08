import csv
from scapy.all import *

# Path to the pcap file
pcap_file = "E:\CapturedPackets1.pcap"

# Read the pcap file
packets = rdpcap(pcap_file)

# Initialize a list to store the extracted features
features = []

# Process each packet in the pcap file
for packet in packets:
    # Check if the packet has the IP layer
    if IP in packet:
        # Extract the source IP address
        src_ip = packet[IP].src

        # Extract the destination IP address
        dst_ip = packet[IP].dst

        # Extract the source port
        src_port = packet.sport if TCP in packet else packet[UDP].sport

        # Extract the destination port
        dst_port = packet.dport if TCP in packet else packet[UDP].dport

        # Extract the protocol type
        protocol = "TCP" if TCP in packet else "UDP"

        # Create a list of the extracted features
        feature = [src_ip, dst_ip, src_port, dst_port, protocol]

        # Add the feature to the list of features
        features.append(feature)

# Define the output CSV file path
output_file = "E:\Blank-CSV-Template.csv"

# Write the features to the CSV file
with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"])
    writer.writerows(features)

print("Features extracted and stored in CSV format.")
