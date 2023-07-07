from scapy.all import *
import glob
import csv
import re
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np

gnum=0
def process_pcap(pcap_folder,AppName,graphsPath):
    #GraphIdNo=0
    if(AppName=="imgur"):
        LabelNum=0
    elif(AppName=="inshorts"):
        LabelNum=1
    elif(AppName=="reddit"):
        LabelNum=2
    elif(AppName=="snapchat"):
        LabelNum=3
    elif(AppName=="spotify"):
        LabelNum=4
    elif(AppName=="twitch"):
        LabelNum=5
    else:
        LabelNum=6

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
            global gnum
            Arithmetic_mean=0
            StandardDeviation=0
            Variance=0
            SourceEdgeIndex=[]
            DstEdgeIndex=[]
            payload_ratio=0
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
            if result=="7" or result=="6":
                prev_packetTime=flow_packets[0].time
                NodeId=0
                NextNode=0
                for Packet in flow_packets:
                    edgeIndexSrc=[]
                    edgeIndexDst=[]
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
                    edgeIndexSrc.append(NodeId)
                    for index in range(NodeId+1,len(flow_packets)):
                        edgeIndexDst.append(index)
                    for index in range((len(flow_packets)-2)-NodeId):
                        edgeIndexSrc.append(index)
                    #node_features = {
                            #'Length': PacketLength,
                            #'IP': dest_ip,
                            #'Port':dest_port,
                            #'window_size': window_size,
                            #'Payload Bits':bitsList 
                    node_features=window_size
                    interArrivalTime=1
                    NextNode=NodeId+1
     
                    NodeId+=1
                    SourceEdgeIndex.extend(edgeIndexSrc)
                    print(SourceEdgeIndex)
                    DstEdgeIndex.extend(edgeIndexDst)

            DstEdgeIndex.append(0)
            interarrival_timesList = []
            
            for i in range(len(SourceEdgeIndex)):
                if(SourceEdgeIndex[i]>DstEdgeIndex[i]):
                   current_packet = SourceEdgeIndex[i]
                   previous_packet = DstEdgeIndex[i]
                   interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                   interarrival_timesList.append(interarrival_time)
                else:
                   current_packet = DstEdgeIndex[i]
                   previous_packet =SourceEdgeIndex[i] 
                   interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                   interarrival_timesList.append(int(interarrival_time))
                   print(interarrival_timesList)
            NpArray=np.array(interarrival_timesList)
            Arithmetic_mean = np.mean(NpArray)
            StandardDeviation=np.std(NpArray)
            Variance=np.var(NpArray)
            edge_attr=[]
            for i in range(len(SourceEdgeIndex)):
                edge_attr.append([int(Arithmetic_mean),int(StandardDeviation),int(Variance)])
            SourceEdgeIndex.extend(DstEdgeIndex)
            with open(graphsPath, 'a', newline='') as csvfileG:
                writerG = csv.writer(csvfileG)
                writerG.writerow([SourceEdgeIndex,edge_attr,[LabelNum],len(flow_packets),[payload_ratio]])   
                        
            gnum+=1
        print("Finshed one PCAP of",AppName)
                        
                
def fetch_subfolder_names(folder_path,graphsPath):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    for subfolder in subfolders:
        # Create the full path to the subfolder
        subfolder_path = os.path.join(folder_path, subfolder)
        files = os.listdir(subfolder_path)
        pcap_folder=subfolder_path
        process_pcap(pcap_folder,subfolder,graphsPath)
        print("APP NAMED"+subfolder+"DONE!")
        



# Specify the path to your folder here
folder_path =r"D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
# nodesPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\mini_multi_dataset\nodes.csv"
# edgesPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\mini_multi_dataset\edges.csv"
graphsPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\mini_multi_dataset\graphs.csv"

#with open(nodesPath, 'w', newline='') as csv_fileN:
    #writer = csv.writer(csv_fileN)
    #writer.writerow(["graph_id","node_id","feat"])
#with open(edgesPath, 'w', newline='') as csv_fileE:
    #writer = csv.writer(csv_fileE)
    #writer.writerow(["graph_id","src_id","dst_id","feat"])
with open(graphsPath, 'w', newline='') as csv_fileG:
    writer = csv.writer(csv_fileG)
    writer.writerow(["edge_index (sequence)","edge_attr (sequence)","y (sequence)","num_nodes (int64)","node_feat (sequence)"])



fetch_subfolder_names(folder_path,graphsPath)
        

print("Completed")








