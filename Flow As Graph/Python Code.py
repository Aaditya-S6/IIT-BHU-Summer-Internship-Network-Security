from scapy.all import *
import glob
import csv
import re
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt



def process_pcap(pcap_file,AppName,nodesPath,edgesPath,graphsPath):
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
   
   
    GraphIdNo=0
    L=list(flows.keys())
    Prev_Flow_key=L[0]
    temp=0
    NodeId=0
    flow_PacketCount=0
    for key, value in flows.items():
        print(key, ":", value)
        print("COUNT",len(value))+

    for flow_key, flow_packets in flows.items():
        temp=temp+1
        if temp==1:
            continue
        if NodeId==len(flow_packets):
            NodeId=0
        if flow_PacketCount==len(flow_packets):
            with open(graphsPath, 'a', newline='') as csvfileG:
                writerG = csv.writer(csvfileG)
                writerG.writerow([GraphIdNo,payload_ratio,AppName])
            GraphIdNo+=1
            
        result = flow_key.rsplit('-', 1)[-1]
        if result == "6":
            sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets )
            recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
            window_size = packet[TCP].window
        elif result=="7":
            sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets )
            recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
            window_size = packet[UDP].window
        if result=="7" or result=="6":
            print(NodeId,result)
            dest_ip = flow_packets[NodeId][IP].dst
            dest_port = flow_packets[NodeId][IP].dport
            Socket= f"{dest_ip}:{dest_port}"
            print("Socket Representation:",Socket)
            if recv_payload_length > 0:
                payload_ratio = sent_payload_length / recv_payload_length
            else:
                payload_ratio = sent_payload_length / (recv_payload_length+1)
            PacketLength=len(flow_packets)
            Bytes=bytes(packet.payload)
            first_32_bits = Bytes[:4]
            binary_string = "".join(format(byte, "08b") for byte in first_32_bits)
            extracted_data.append(binary_string)
            lst = [int(bit) for bit in extracted_data[0]]
            node_features = {
                'Length': PacketLength,
                'Socket': Socket,
                'window_size': window_size,
                'Payload Bits':lst }
            if NodeId<len(flow_packets):
                interArrivalTime=flow_packets[NodeId+1].time-flow_packets[NodeId].time
            elif NodeId==0:
                interArrivalTime=flow_packets[len(flow_packets)-1].time-flow_packets[0].time
            else:
                interArrivalTime=flow_packets[NodeId]-flow_packets[0].time
            GraphLabel=AppName
            with open(nodesPath, 'a', newline='') as csvfileN:
                writerN = csv.writer(csvfileN)
                writerN.writerow([GraphIdNo,NodeId,node_features])
            with open(edgesPath, 'a', newline='') as csvfileE:
                writerE = csv.writer(csvfileE)
                writerE.writerow([GraphIdNo,NodeId,NodeId+1,interArrivalTime])
            Prev_flow_key=flow_key
            flow_PacketCount+=1
            NodeId+=1
            
                
            
        
        
                
                



def fetch_subfolder_names(folder_path,nodesPath,edgesPath,graphsPath):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    for subfolder in subfolders:
        # Create the full path to the subfolder
        subfolder_path = os.path.join(folder_path, subfolder)
        files = os.listdir(subfolder_path)
        pcap_folder=subfolder_path
        for filename in os.listdir(pcap_folder):
                file_path = os.path.join(pcap_folder, filename)
                process_pcap(file_path,subfolder,nodesPath,edgesPath,graphsPath)
                print("Finished processing one pcap")
        print("App named"+subfolder+"Done")
        



# Specify the path to your folder here
folder_path ="D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
nodesPath=r'C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\nodes.csv'
edgesPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\edges.csv"
graphsPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\CSV folder\graphs.csv"

with open(nodesPath, 'w', newline='') as csv_fileN:
    writer = csv.writer(csv_fileN)
    writer.writerow(["graph_id","node_id","feat"])
with open(edgesPath, 'w', newline='') as csv_fileE:
    writer = csv.writer(csv_fileE)
    writer.writerow(["graph_id","src_id","dst_id","feat"])
with open(graphsPath, 'w', newline='') as csv_fileG:
    writer = csv.writer(csv_fileG)
    writer.writerow(["graph_id","feat","label"])



fetch_subfolder_names(folder_path,nodesPath,edgesPath,graphsPath)
        

print("Completed")








