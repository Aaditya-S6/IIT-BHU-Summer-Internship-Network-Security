import os
import csv
import json
from scapy.all import *


def process_pcap(pcap_file, app_name, nodes_path, edges_path, graphs_path):
    packets = rdpcap(pcap_file)
    flows = {}  # Dictionary to store unique flow keys
    extracted_data = []

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Check if the packet has a UDP or TCP layer
            if packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            elif packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                # Skip packets without UDP or TCP layer
                continue

            # Reverse the flow key for bidirectional flows
            reverse_flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

            # Combine both flow keys to handle bidirectional flows
            combined_flow_key = frozenset([flow_key, reverse_flow_key])

            if flow_key in flows:
                flows[flow_key].append(packet)
            elif reverse_flow_key in flows:
                flows[reverse_flow_key].append(packet)
            elif combined_flow_key in flows:
                flows[combined_flow_key].append(packet)
            else:
                flows[flow_key] = [packet]

    idx = 0
    graph_id = 0
    l = list(flows.keys())
    prev_flow_key = l[0]
    
    with open(nodes_path, 'a', newline='') as csvfileN, open(edges_path, 'a', newline='') as csvfileE, \
            open(graphs_path, 'a', newline='') as csvfileG:
        writerN = csv.writer(csvfileN)
        writerE = csv.writer(csvfileE)
        writerG = csv.writer(csvfileG)

        for flow_key, flow_packets in flows.items():
            if flow_key == l[0]:
                continue
            
            if prev_flow_key != flow_key:
                idx = 0
                graph_id += 1

            result = flow_key.rsplit('-', 1)[-1]
            if result == "6":
                sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets)
                recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key.split('-')[0])
                window_size = flow_packets[idx][TCP].window
            elif result == "17":
                sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets)
                recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key.split('-')[0])
                window_size = flow_packets[idx][UDP].window
            else:
                # Skip packets with unsupported protocols
                continue
            
            dest_ip = flow_packets[idx][IP].dst
            dest_port = flow_packets[idx][IP].dport
            socket = f"{dest_ip}:{dest_port}"
            payload_ratio = sent_payload_length / (recv_payload_length + 1)
            packet_length = len(flow_packets)
            bytes_data = bytes(flow_packets[idx].payload)
            first_32_bits = bytes_data[:4]
            binary_string = "".join(format(byte, "08b") for byte in first_32_bits)
            extracted_data.append(binary_string)
            lst = [int(bit) for bit in extracted_data[0]]
            node_id = idx
            idx += 1
            node_features = {
                'Length': packet_length,
                'Socket': socket,
                'window_size': window_size,
                'Payload Bits': lst
            }
            
            if idx < len(flows):
                inter_arrival_time = flow_packets[idx + 1].time - flow_packets[idx].time
            else:
                inter_arrival_time = flow_packets[idx] - flow_packets[0].time
                
            graph_label = app_name

            writerN.writerow([graph_id, node_id, json.dumps(node_features)])
            writerE.writerow([graph_id, idx, idx + 1, inter_arrival_time])
            writerG.writerow([graph_id, payload_ratio, graph_label])

            prev_flow_key = flow_key


def fetch_subfolder_names(folder_path, nodes_path, edges_path, graphs_path):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    
    with open(nodes_path, 'w', newline='') as csv_fileN, open(edges_path, 'w', newline='') as csv_fileE, \
            open(graphs_path, 'w', newline='') as csv_fileG:
        writerN = csv.writer(csv_fileN)
        writerE = csv.writer(csv_fileE)
        writerG = csv.writer(csv_fileG)
        writerN.writerow(["graph_id", "node_id", "feat"])
        writerE.writerow(["graph_id", "src_id", "dst_id", "feat"])
        writerG.writerow(["graph_id", "feat", "label"])

        for subfolder in subfolders:
            subfolder_path = os.path.join(folder_path, subfolder)
            pcap_folder = subfolder_path

            for filename in os.listdir(pcap_folder):
                file_path = os.path.join(pcap_folder, filename)
                process_pcap(file_path, subfolder, nodes_path, edges_path, graphs_path)
                print("Finished processing one pcap")

            print("App named " + subfolder + " done")


# Specify the paths to your folders here
folder_path = r"D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
nodes_path = r'C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\nodes.csv'
edges_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\edges.csv"
graphs_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\graphs.csv"

fetch_subfolder_names(folder_path, nodes_path, edges_path, graphs_path)

print("Completed")
