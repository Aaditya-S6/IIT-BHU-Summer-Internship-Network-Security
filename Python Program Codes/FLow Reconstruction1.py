from scapy.all import *
import os
import csv

def calculate_payload_ratio(pcap_folder, app_name):
    pcap_files = [f for f in os.listdir(pcap_folder) if f.endswith('.pcap')]

    output_filename = "D:\IIT BHU Intership\CSV Files\csv10.csv"
    with open(output_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['App Name', 'Payload Ratio'])

        for pcap_file in pcap_files:
            pcap_path = os.path.join(pcap_folder, pcap_file)
            packets = rdpcap(pcap_path)

            flows = {}  # Dictionary to store bidirectional flows

            for packet in packets:
                if 'TCP' in packet and 'Raw' in packet:
                    src_ip = packet['IP'].src
                    dst_ip = packet['IP'].dst
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    flow_key = (src_ip, src_port, dst_ip, dst_port)

                    if flow_key in flows:
                        flow = flows[flow_key]
                    else:
                        flow = {
                            'sent_payload': 0,
                            'received_payload': 0
                        }
                        flows[flow_key] = flow

                    if packet['TCP'].sport == 80:  # Sent from sender to receiver
                        flow['sent_payload'] += len(packet['Raw'].load)
                    elif packet['TCP'].dport == 80:  # Sent from receiver to sender
                        flow['received_payload'] += len(packet['Raw'].load)

            for flow_key, flow in flows.items():
                sent_payload = flow['sent_payload']
                received_payload = flow['received_payload']

                if received_payload > 0:
                    payload_ratio = sent_payload / received_payload
                    writer.writerow([app_name, payload_ratio])

    print(f"Payload ratios extracted and saved in {output_filename}")

# Example usage
pcap_folder_path = "D:\IIT BHU Intership\ssss"
app_name = 'YouTube'

calculate_payload_ratio(pcap_folder_path, app_name)
