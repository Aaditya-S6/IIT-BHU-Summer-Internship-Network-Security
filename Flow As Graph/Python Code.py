from scapy.all import *
import glob
import csv
import re
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


def process_pcap(pcap_file,output_file,AppName):
    
    packets = rdpcap(pcap_file)
    flows = {}  # Dictionary to store unique flow keys

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Check if the packet has a UDP or TCP layer
            if packet[IP].proto==17:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            elif packet[IP].proto==6:
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

   
    idx=0
    L=list(flows.keys())
    G = nx.Graph()
    Prev_Flow_key=L[0]
    for flow_key, flow_packets in flows.items():
        if Prev_Flow_key!=flow_key:
            idx=0
            
            G.clear()
            
        result = flow_key.rsplit('-', 1)[-1]
        if result == "6":
            sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets )
            recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
             window_size = packet[TCP].window
        elif result=="7":
            sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets )
            recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
             window_size = packet[UDP].window

        dest_ip = flow_packets[idx][IP].dst
        print(dest_ip)
        dest_port = flow_packets[idx][IP].dport
        Socket= f"{dest_ip}:{dest_port}"
        print("Socket Representation:",Socket)
        if recv_payload_length > 0:
            payload_ratio = sent_payload_length / recv_payload_length
        else:
            payload_ratio = sent_payload_length / (recv_payload_length+1)
        PacketLength=len(flow_packets)
        Bytes=bytes(packet.payload)
        first_32_bits = flow[:4]
        binary_string = "".join(format(byte, "08b") for byte in first_32_bits)
        extracted_data.append(binary_string)
        lst = [int(bit) for bit in extracted_data[0]] 
        node_id = idx
        idx=idx+1
        node_features = {
            'Length': PacketLength,
            'Socket': Socket,
            'window_size': window_size,
            'Payload Bits':lst }
        
        G.add_node(node_id, **node_features)
        
        
                
                



def fetch_subfolder_names(folder_path,csv_folder_path):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    CSVsubfolders = [name for name in os.listdir(csv_folder_path) if os.path.isdir(os.path.join(csv_folder_path, name))]
    # Loop through each subfolder
    for subfolder in subfolders:
        # Create the full path to the subfolder
        subfolder_path = os.path.join(folder_path, subfolder)
        print(subfolder)
        print(subfolder_path)
        files = os.listdir(subfolder_path)
        CSVFileName=subfolder
        pcap_folder=subfolder_path
        output_file = os.path.join(csv_folder_path,CSVFileName)
        for filename in os.listdir(pcap_folder):
                file_path = os.path.join(pcap_folder, filename)
                process_pcap(file_path, output_file,subfolder)
                print("Finished processing one pcap")
        print("App named"+subfolder+"Done")
        



# Specify the path to your folder here
folder_path ="D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
csv_folder_path ="C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder"


fetch_subfolder_names(folder_path,csv_folder_path)
        

print("Completed")








