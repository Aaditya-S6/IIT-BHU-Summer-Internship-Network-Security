from scapy.all import *
import glob
import csv
import re
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
from decimal import Decimal
import json

class flowData:
    def __init__(self,edge_index,edge_attr,y,num_nodes,node_feat):
        self.edge_index=edge_index
        self.edge_attr=edge_attr
        self.y=y
        self.num_nodes=num_nodes
        self.node_feat=node_feat
gnum=0
def process_pcap(pcap_folder,AppName,graphsPath):
    counter=0
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
                #combined_flow_key = frozenset([flow_key, reverse_flow_key])

                if flow_key in flows:
                    flows[flow_key].append(packet)
                elif reverse_flow_key in flows:
                    flows[reverse_flow_key].append(packet)
                # if combined_flow_key in flows:
                #     flows[combined_flow_key].append(packet)
                
                else:
                    flows[flow_key] = [packet]
        for flow_key, flow_packets in flows.items():
            if(len(flow_packets)>50):
                continue
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
                NodeId=0
                edgeIndexSrc=[]
                edgeIndexDst=[]
                for Packet in flow_packets:
                    edgeIndexSrc.append(NodeId)
                    for index in range(NodeId+1,len(flow_packets)):
                        edgeIndexDst.append(index)
                    for index in range((len(flow_packets)-2)-NodeId):
                        edgeIndexSrc.append(index)
                    NodeId+=1
                SourceEdgeIndex.extend(edgeIndexSrc)
                DstEdgeIndex.extend(edgeIndexDst)
            if(len(SourceEdgeIndex)==0):
                continue
            DstEdgeIndex.append(0)
            interarrival_timesList = []
            for i in range(len(SourceEdgeIndex)):
                if(SourceEdgeIndex[i]>DstEdgeIndex[i]):
                   current_packet = SourceEdgeIndex[i]
                   previous_packet = DstEdgeIndex[i]
                   interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                   interarrival_timesList.append(int(interarrival_time))
                else:
                   current_packet = DstEdgeIndex[i]
                   previous_packet =SourceEdgeIndex[i] 
                   interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                   interarrival_timesList.append(int(interarrival_time))
            if(len(interarrival_timesList)==0):
                continue
            NpArray=np.array(interarrival_timesList)
            StandardDeviation=np.std(NpArray)
            Variance=np.var(NpArray)
            Arithmetic_mean=np.mean(NpArray)
            if(StandardDeviation==0 and Variance==0 and Arithmetic_mean==0):
                continue
            
            edge_attr=[]
            PacketLen=[]
            for i in range(len(flow_packets)):
                PacketLen.append(len(flow_packets[i]))
            NPArrayPacket=np.array(PacketLen)
            MeanLength=np.mean(NPArrayPacket)
            NodeFeatures=[]
            #dest_ip = flow_packets[0][IP].dst 
            dest_port = flow_packets[0][IP].dport
            #Socket= f"{dest_ip}:{dest_port}"

            flowDuration=abs(flow_packets[len(flow_packets)-1].time-flow_packets[0].time)
            for i in range(len(flow_packets)):
                NodeFeatures.append([int(payload_ratio),dst_port,len(flow_packets[i]),int(StandardDeviation),int(Variance),int(payload_ratio),dst_port,len(flow_packets[i]),int(StandardDeviation)])
            for i in range(len(SourceEdgeIndex)):
                edge_attr.append([int(Arithmetic_mean),int(abs(flow_packets[SourceEdgeIndex[i]].time-flow_packets[DstEdgeIndex[i]].time)),int(MeanLength)])
            FlowInstance=flowData([SourceEdgeIndex,DstEdgeIndex],edge_attr,[LabelNum],len(flow_packets),NodeFeatures)
            with open(graphsPath,"a") as f:
                json.dump(FlowInstance.__dict__,f) 
                        
            gnum+=1
            print("One flow of",AppName,"Done")
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

graphsPath=r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\graphs.json"





fetch_subfolder_names(folder_path,graphsPath)
        

print("Completed")








