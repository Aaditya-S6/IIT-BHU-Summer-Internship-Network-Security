from scapy.all import *
import numpy as np
import csv
import os

pcap_folder_path = r"D:\IIT BHU Intership\ssss"
app_name = 'YouTube'
output_file = r"D:\IIT BHU Intership\CSV Files\csv11.csv"

def calculate_payload_ratio(pcap_folder, app_name):
    pcap_files = [f for f in os.listdir(pcap_folder) if f.endswith('.pcap')]
    for pcap_file in pcap_files:
        flow_features = []
        # Define the flow-level features to extract
        desired_features = [ 'Payload Ratio']
       # Create dictionaries to store flows and flow-level features
        upstream_flows = {}
        # Read the pcap file
        packets = rdpcap(pcap_file)
        # Process each packet in the pcap file
        for packet in packets:
            if 'IP' in packet and 'Raw' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
                conversation_key = (src_ip, src_port, dst_ip, dst_port)

                if conversation_key in conversations:
                    conversation = conversations[conversation_key]
                else:
                    conversation = {
                        'src_to_dst_length': 0,
                        'dst_to_src_length': 0
                    }
                    conversations[conversation_key] = conversation

                if packet['TCP'].sport == src_port:  # Sent from source to destination
                    conversation['src_to_dst_length'] += len(packet['Raw'].load)
                else:  # Sent from destination to source
                    conversation['dst_to_src_length'] += len(packet['Raw'].load)

        for conversation_key, conversation in conversations.items():
            src_ip, src_port, dst_ip, dst_port = conversation_key
            src_to_dst_length = conversation['src_to_dst_length']
            dst_to_src_length = conversation['dst_to_src_length']
            total_length = src_to_dst_length + dst_to_src_length


            flow_payload_ratio =src_to_dst_length/dst_to_src_length

            # Create a dictionary to store the desired flow features
            flow_features_dict = {
                'Feature': desired_features,
                'Value': [ flow_payload_ratio
                    
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


calculate_payload_ratio(pcap_folder_path, app_name)
