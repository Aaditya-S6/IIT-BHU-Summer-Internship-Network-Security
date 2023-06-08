from scapy.all import *
import numpy as np
import csv

# Path to the pcap file
pcap_file = "E:\DataSet\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\youtube-20230531T093352Z-001\youtube\youtube 1.pcap"
output_file ="E:\CSV9.csv"
flow_features = []

# Define the flow-level features to extract
desired_features = [
    'Flow Payload Length', 'Flow Length', 'Flow Start Time', 'Flow End Time',
    'Flow Packet Count', 'Flow Duration', 'Flow Packet Rate', 'Flow Ratio',
    'Flow Encryption', 'Flow Encryption Type', 'Flow Payload'
]

# Create dictionaries to store flows and flow-level features
upstream_flows = {}

# Read the pcap file
packets = rdpcap(pcap_file)

# Process each packet in the pcap file
for packet in packets:
    if TCP in packet:
        # Get the source IP, destination IP, source port, and destination port
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Create a unique key for the TCP flow
        flow_key = (src_ip, dst_ip, src_port, dst_port)

        # Calculate packet length and arrival time
        packet_len = len(packet)
        arrival_time = packet.time if 'time' in packet else 0

        # Add the packet length and arrival time to the corresponding flow
        if flow_key in upstream_flows:
            upstream_flows[flow_key]['packet_lens'].append(packet_len)
            upstream_flows[flow_key]['arrival_times'].append(arrival_time)
        else:
            upstream_flows[flow_key] = {'packet_lens': [
                packet_len], 'arrival_times': [arrival_time]}

# Calculate flow-level features for upstream flows
for flow_key, flow_data in upstream_flows.items():
    packet_lens = np.array(flow_data['packet_lens'])
    arrival_times = np.array(flow_data['arrival_times'])

    # Calculate flow-level features
    flow_payload_length = np.sum(packet_lens)
    flow_length = len(packet_lens)
    flow_start_time = np.min(arrival_times)
    flow_end_time = np.max(arrival_times)

    # Calculate flow packet rate (handle divide by zero error)
    flow_duration = flow_end_time - flow_start_time
    if flow_duration != 0:
        flow_packet_rate = flow_packet_count / flow_duration
    else:
        flow_packet_rate = 0

    flow_ratio = np.sum(packet_lens) / flow_length
    flow_encryption = "Unknown"  # Add your logic to determine flow encryption
    flow_encryption_type = "Unknown"  # Add your logic to determine flow encryption type
    flow_payload = ""  # Add your logic to extract flow payload

    # Create a dictionary to store the desired flow features
    flow_features_dict = {
        'Feature': desired_features,
        'Value': [
            flow_payload_length, flow_length, flow_start_time, flow_end_time,
            flow_packet_count, flow_duration, flow_packet_rate, flow_ratio,
            flow_encryption, flow_encryption_type, flow_payload
        ]
    }

    # Append the flow features to the list
    flow_features.append(flow_features_dict)

# Write the flow-level features to the CSV file
with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(desired_features)
    for flow in flow_features:
        writer.writerow(flow['Value'])

print("Flow level features written in CSV file")
