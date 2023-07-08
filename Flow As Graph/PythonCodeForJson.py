import json
from scapy.all import *
import glob
import os
import numpy as np

gnum = 0

def process_pcap(pcap_folder, AppName, graphsPath):
    counter = 0
    if AppName == "imgur":
        LabelNum = 0
    elif AppName == "inshorts":
        LabelNum = 1
    elif AppName == "reddit":
        LabelNum = 2
    elif AppName == "snapchat":
        LabelNum = 3
    elif AppName == "spotify":
        LabelNum = 4
    elif AppName == "twitch":
        LabelNum = 5
    else:
        LabelNum = 6

    for filename in os.listdir(pcap_folder):
        pcap_file = os.path.join(pcap_folder, filename)
        packets = rdpcap(pcap_file)
        flows = {}  # Dictionary to store unique flow keys
        extracted_data = []

        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                # Check if the packet has a UDP or TCP layer
                if packet[IP].proto == 17:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                elif packet[IP].proto == 6:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                else:
                    # Skip packets without UDP or TCP layer
                    continue

                reverse_flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
                if flow_key in flows:
                    flows[flow_key].append(packet)
                elif reverse_flow_key in flows:
                    flows[reverse_flow_key].append(packet)
                else:
                    flows[flow_key] = [packet]

        for flow_key, flow_packets in flows.items():
            if len(flow_packets) > 100:
                continue
            global gnum
            Arithmetic_mean = 0
            StandardDeviation = 0
            Variance = 0
            SourceEdgeIndex = []
            DstEdgeIndex = []
            payload_ratio = 0
            result = flow_key.rsplit('-', 1)[-1]
            
            if result == "6":
                sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets)
                recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key[0])
            elif result == "7":
                sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets)
                recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key[0])

            if recv_payload_length > 0:
                payload_ratio = sent_payload_length / recv_payload_length
            else:
                payload_ratio = sent_payload_length / (recv_payload_length + 1)

            if result == "7" or result == "6":
                NodeId = 0
                edgeIndexSrc = []
                edgeIndexDst = []
                for Packet in flow_packets:
                    edgeIndexSrc.append(NodeId)
                    for index in range(NodeId + 1, len(flow_packets)):
                        edgeIndexDst.append(index)
                    for index in range((len(flow_packets) - 2) - NodeId):
                        edgeIndexSrc.append(index)
                    NodeId += 1
                SourceEdgeIndex.extend(edgeIndexSrc)
                DstEdgeIndex.extend(edgeIndexDst)

            if len(SourceEdgeIndex) == 0:
                continue

            DstEdgeIndex.append(0)
            interarrival_timesList = []
            for i in range(len(SourceEdgeIndex)):
                if SourceEdgeIndex[i] > DstEdgeIndex[i]:
                    current_packet = SourceEdgeIndex[i]
                    previous_packet = DstEdgeIndex[i]
                    interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                    interarrival_timesList.append(int(interarrival_time))
                else:
                    current_packet = DstEdgeIndex[i]
                    previous_packet = SourceEdgeIndex[i]
                    interarrival_time = flow_packets[current_packet].time - flow_packets[previous_packet].time
                    interarrival_timesList.append(int(interarrival_time))
            if len(interarrival_timesList) == 0:
                continue

            NpArray = np.array(interarrival_timesList)
            StandardDeviation = np.std(NpArray)
            Variance = np.var(NpArray)

            edge_attr = []
            for i in range(len(SourceEdgeIndex)):
                edge_attr.append([int(Arithmetic_mean), int(StandardDeviation), int(Variance)])

            extracted_data.append({
                "edge_index":[SourceEdgeIndex,DstEdgeIndex],
                "edge_attr":edge_attr,
                "y": [LabelNum],
                "num_packets": len(flow_packets),
                "node_feat": [int(payload_ratio)]
            })

            gnum += 1

        with open(graphsPath, 'a') as json_file:
            json.dump(extracted_data, json_file)
            json_file.write('\n')

def fetch_subfolder_names(folder_path, graphsPath):
    subfolders = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
    for subfolder in subfolders:
        subfolder_path = os.path.join(folder_path, subfolder)
        pcap_folder = subfolder_path
        process_pcap(pcap_folder, subfolder, graphsPath)
        print("APP NAMED" + subfolder + "DONE!")

# Specify the path to your folder here
folder_path = r"D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
graphsPath = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\mini_multi_dataset\graphs.json"
fetch_subfolder_names(folder_path, graphsPath)

print("Completed")
