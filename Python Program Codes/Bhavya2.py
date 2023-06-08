from scapy.all import *
import csv
import os
def SpaceString(Str):
     result_string = ' '.join(Str)
     return result_string
def hex_to_binary(hex_string):
    decimal_value = int(hex_string, 16)
    binary_string = bin(decimal_value)[2:]  
    return binary_string.zfill(len(hex_string) * 4) 

def process_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    flows = {}
    for packet in packets:
        if UDP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet[UDP].sport
            dport = packet[UDP].dport
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
            #packets = rdpcap("D:\IIT BHU Intership\ssss\BACnet-1.pcap")
            for packet in packets:
                     if UDP in packet:
                         udp_payload = packet[UDP].payload.load
                         Str=str(udp_payload.hex())
                         break; 
            S=slice(8)
            Bh=hex_to_binary(Str[S])
            Bhavya=SpaceString(Bh)
            lst=Bhavya.split()
            print(Str[S])
            print(hex_to_binary(Str[S]))
            print(lst)
            if len(lst)>31:
                writer.writerow([lst[0], lst[1] ,lst[2], lst[3] ,lst[4], lst[5] ,lst[6], lst[7] ,lst[8], lst[9] ,lst[10],
                              lst[11] ,lst[12], lst[13] ,lst[14], lst[15] ,lst[16], lst[17] ,lst[18], lst[19] ,lst[20], lst[21] ,lst[22], lst[23] ,
                            lst[24], lst[25] ,lst[26], lst[27] ,lst[28], lst[29] ,lst[30], lst[31],'BackNET'])
                
    
            print(f"Flow information stored in {output_file}.")



    


# Usage example
pcap_folder ="D:\IIT BHU Intership\ssss"
output_file = "D:\IIT BHU Intership\CSV Files\Bhavya.csv"

with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['bit0','bit1','bit2','bit3','bit4','bit5','bit6','bit7','bit8','bit9','bit10','bit11','bit12','bit13','bit14','bit15',
                     'bit16','bit17','bit18','bit19','bit20','bit21','bit22','bit23','bit24','bit25','bit26','bit27','bit28','bit29','bit30','bit31','Class'])

for filename in os.listdir(pcap_folder):
    file_path = os.path.join(pcap_folder, filename)
    process_pcap(file_path, output_file)
    print("Finished processing one pcap")

print("Completed")
