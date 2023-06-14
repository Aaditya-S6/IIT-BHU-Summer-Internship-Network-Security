from scapy.all import *
import csv
import os

import csv



def process_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    flows = {}
    
    for packet in packets:
        if TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flow_key = (ip_src, ip_dst, sport, dport)
            rev_flow_key = (ip_dst, ip_src, dport, sport)
            
            if flow_key in flows:
                flows[flow_key].append(packet)
            elif rev_flow_key in flows:
                flows[rev_flow_key].append(packet)
            
            else:
                flows[flow_key] = [packet]
    
    with open(output_file, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # writer.writerow(['App Name', 'Payload Ratio'])
        i=0
        for flow_key, flow_packets in flows.items():
            sent_payload_length = sum(len(p[TCP].payload) for p in flow_packets)
            recv_payload_length = sum(len(p[TCP].payload) for p in flow_packets if p[IP].src == flow_key[0])  
            dest_ip = flow_packets[0][IP].dst
            dest_port = flow_packets[0][TCP].dport
            Socket= f"{dest_ip}:{dest_port}"
            i=i+1
            print("Socket Representation:",Socket)
            
            
            if recv_payload_length > 0: 
                payload_ratio = sent_payload_length / recv_payload_length
            else:
                payload_ratio = sent_payload_length / (recv_payload_length+1)
                
            writer.writerow(["Imgur", payload_ratio,Socket])
    
    print(f"Flow information stored in {output_file}.")

# Usage example
pcap_folder ="D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\imgur-20230531T091233Z-001\imgur"
output_file = "D:\IIT BHU Intership\CSV Files\csv16.csv"

#with open(output_file, 'w', newline='') as csvfile:
#    writer = csv.writer(csvfile)
#    writer.writerow(['App Name', 'Payload Ratio','Socket'])

for filename in os.listdir(pcap_folder):
    file_path = os.path.join(pcap_folder, filename)
    process_pcap(file_path, output_file)
    print("Finished processing one pcap")

print("Completed")
