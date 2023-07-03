from scapy.all import *
import glob
import csv
import re


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

    with open(output_file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        i=0
        for flow_key, flow_packets in flows.items():
             print(type(flow_key))
             result = flow_key.rsplit('-', 1)[-1]
             
             if result == "6":
                  sent_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets )
                  recv_payload_length = sum(len(str(p[TCP].payload)) for p in flow_packets if p[IP].src == flow_key[0])  
             elif result=="7":
                  sent_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets )
                  recv_payload_length = sum(len(str(p[UDP].payload)) for p in flow_packets if p[IP].src == flow_key[0])   

                 
             dest_ip = flow_packets[0][IP].dst 
             dest_port = flow_packets[0][IP].dport
             Socket= f"{dest_ip}:{dest_port}"
             i=i+1
             print("Socket Representation:",Socket)
            
            
             if recv_payload_length > 0:
                  payload_ratio = sent_payload_length / recv_payload_length
             else:
                  payload_ratio = sent_payload_length / (recv_payload_length+1)
                
             writer.writerow([AppName, payload_ratio,Socket]) 



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
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['App Name','Payload Ratio','Socket']);
        for filename in os.listdir(pcap_folder):
                file_path = os.path.join(pcap_folder, filename)
                process_pcap(file_path, output_file,subfolder)
                print("Finished processing one pcap")
        print("App named"+subfolder+"Done")
        



# Specify the path to your folder here
folder_path ="D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\DataSet All Apps"
csv_folder_path ="C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\App as Graph\CsvFolder"


fetch_subfolder_names(folder_path,csv_folder_path)
        
output_file = "D:\IIT BHU Intership\CSV Files\csv16.csv"

print("Completed")








