from scapy.all import *
import os

# Path to the folder containing the pcap files
folder_path = "D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\youtube-20230531T093352Z-001\youtube"+

# Iterate through the folders
for app_folder in os.listdir(folder_path):
    app_folder_path = os.path.join(folder_path, app_folder)
    
    # Check if the item is a folder
    if os.path.isdir(app_folder_path):
        print("Processing folder:", app_folder)
        
        # Iterate through pcap files in the folder
        for pcap_file in os.listdir(app_folder_path):
            pcap_file_path = os.path.join(app_folder_path, pcap_file)
            
            # Check if the item is a file ending with .pcap
            if os.path.isfile(pcap_file_path) and pcap_file.endswith(".pcap"):
                print("Processing file:", pcap_file)
                
                # Read the pcap file
                packets = rdpcap(pcap_file_path)
                
                # Extract packet information and reconstruct flows
                flows = {}
                for packet in packets:
                    # Extract relevant information from the packet
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = packet[IP].proto
                    payload = packet[TCP].payload
                    
                    # Combine packet information into a flow key
                    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                    
                    # Append packet payload to the corresponding flow
                    if flow_key in flows:
                        flows[flow_key] += payload
                    else:
                        flows[flow_key] = payload
                
                # Sort the packets based on sequence numbers or timestamps (if available)
                sorted_flows = sorted(flows.items(), key=lambda x: x[0])
                
                # Store the reconstructed flows or perform further analysis
                for flow_key, flow_payload in sorted_flows:
                    # Here, you can process each flow as desired
                    # For example, you can print the flow information
                    print("Flow:", flow_key)
                    print("Payload:", flow_payload)
                    
                print("Flow reconstruction completed for file:", pcap_file)
            
        print("Flow reconstruction completed for folder:", app_folder)
