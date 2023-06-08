import csv
from scapy.all import *

def extract_flow_features(pcap_file):
    flows = {}
    packets = rdpcap(pcap_file)

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            flow_key = (src_ip, dst_ip, src_port, dst_port)
            if flow_key not in flows:
                flows[flow_key] = {
                    'start_time': packet.time,
                    'end_time': packet.time,
                    'packet_count': 0,
                    'payload_length': 0
                }
            
            flows[flow_key]['end_time'] = packet.time
            flows[flow_key]['packet_count'] += 1
            flows[flow_key]['payload_length'] += len(packet[TCP].payload)

    flow_features = []
    for flow_key, flow_info in flows.items():
        flow_duration = flow_info['end_time'] - flow_info['start_time']
        flow_packet_rate = flow_info['packet_count'] / flow_duration
        flow_payload_length = flow_info['payload_length']
        flow_length = flow_info['packet_count'] * flow_payload_length
        flow_ratio = flow_payload_length / flow_length

        # Assuming you have flow encryption information available
        flow_encryption = True
        flow_encryption_type = 'TLS'  # Example encryption type
        
        flow_features.append([
            flow_payload_length,
            flow_length,
            flow_info['start_time'],
            flow_info['end_time'],
            flow_duration,
            flow_info['packet_count'],
            flow_packet_rate,
            flow_ratio,
            flow_encryption,
            flow_encryption_type,
            packet[TCP].payload  # Example payload extraction
        ])

    return flow_features

def write_to_csv(data, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'Flow Payload Length',
            'Flow Length',
            'Flow Start Time',
            'Flow End Time',
            'Flow Duration',
            'Flow Packet Count',
            'Flow Packet Rate',
            'Flow Ratio',
            'Flow Encryption',
            'Flow Encryption Type',
            'Flow Payload'
        ])
        writer.writerows(data)

# Replace 'input.pcap' with your pcap file path
flow_features = extract_flow_features('E:\CapturedPackets1.pcap')

# Replace 'output.csv' with the desired output CSV file path
write_to_csv(flow_features, 'E:\CSV6.csv')
