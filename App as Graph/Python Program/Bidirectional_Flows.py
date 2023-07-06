from scapy.all import *
import glob
import csv
import re
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

gnum=0
def process_pcap(pcap_folder,AppName,graph_edges,graph_properties):
    #GraphIdNo=0
    global gnum
    for filename in os.listdir(pcap_folder):
        pcap_file = os.path.join(pcap_folder, filename)
        packets = rdpcap(pcap_file)
        flows = {}  # Dictionary to store unique flow keys
        extracted_data=[]


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
   
        for flow_key, flow_packets in flows.items():
            result = flow_key.rsplit('-', 1)[-1]
            if result == "6":
                sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets )
                recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
                    
            elif result=="7":
                sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets )
                recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
                    
            if recv_payload_length > 0:
                payload_ratio = sent_payload_length / recv_payload_length
            else:
                payload_ratio = sent_payload_length / (recv_payload_length+1)
            with open(graph_properties, 'a', newline='') as csvfileG:
                writerG = csv.writer(csvfileG)
                if AppName=="imgur":
                    label=1
                elif AppName=="inshorts":
                    label=2
                elif AppName=="reddit":
                    label=3
                elif AppName=="snapchat":
                    label=4
                elif AppName=="spotify":
                    label=5
                elif AppName=="twitch":
                    label=6
                else:
                    label=7
                writerG.writerow([gnum,label,len(flow_packets)])        
            if result=="7" or result=="6":
                prev_packetTime=flow_packets[0].time
                NodeId=0
                NextNode=0
                for Packet in flow_packets[1:]:
                    if result == "6":
                        window_size = Packet[TCP].window
                    elif result=="7":
                        window_size = Packet[UDP].window
                
                    dest_ip = 1
                    dest_port =Packet[IP].dport
                    PacketLength=len(Packet)
                    Bytes=bytes(Packet.payload)
                    first_32_bits = Bytes[:4]
                    binary_string = "".join(format(byte, "08b") for byte in first_32_bits)
                    extracted_data.append(binary_string)
                    lst = [int(bit) for bit in extracted_data[0]]
                    bitsList = np.array(lst)
                    #node_features = {
                            #'Length': PacketLength,
                            #'IP': dest_ip,
                            #'Port':dest_port,
                            #'window_size': window_size,
                            #'Payload Bits':bitsList }
                    node_features=window_size
                    interArrivalTime=1
                    NextNode=NodeId+1
                    if NodeId==len(flow_packets)-1:
                       NextNode=0
                    with open(graph_edges, 'a', newline='') as csvfileN:
                        writerN = csv.writer(csvfileN)
                        writerN.writerow([gnum,NodeId,NextNode,Node_feature])
                    NodeId+=1
                        
            gnum+=1
        print("Finshed one PCAP of",AppName)
                        
                
def fetch_subfolder_names(folder_path,graph_edges,graph_properties):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    for subfolder in subfolders:
        # Create the full path to the subfolder
        subfolder_path = os.path.join(folder_path, subfolder)
        files = os.listdir(subfolder_path)
        pcap_folder=subfolder_path
        process_pcap(pcap_folder,subfolder,graph_edges,graph_properties)
        print("APP NAMED"+subfolder+"DONE!")
        



# Specify the path to your folder here
folder_path="D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
graph_edges="C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\App as Graph\CsvFolder\graph_edges.csv"
graph_properties="C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\App as Graph\CsvFolder\graph_properties.csv"

with open(graph_edges, 'w', newline='') as csv_fileN:
    writer = csv.writer(csv_fileN)
    writer.writerow(["graph_id","src","dst"])
with open(graph_properties, 'w', newline='') as csv_fileE:
    writer = csv.writer(csv_fileE)
    writer.writerow(["graph_id","label","num_nodes"])

fetch_subfolder_names(folder_path,graph_edges,graph_properties)
        

print("Completed")








