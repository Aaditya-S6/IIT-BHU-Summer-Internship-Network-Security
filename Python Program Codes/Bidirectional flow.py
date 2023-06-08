from scapy.all import *
import pandas as pd
import csv

pcap_file = "D:\IIT BHU Intership\CSV Files\BACnet-1.pcap"

packets = rdpcap(pcap_file)

packet_features = []

for packet in packets:
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Source Port:", src_port)
        print("Destination Port:", dst_port)

        syn_packet = IP(src=src_ip, dst=dst_ip) / \
            TCP(sport=src_port, dport=dst_port, flags="S")
        syn_ack_response = sr1(syn_packet, verbose=0)

        ack_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", ack=syn_ack_response.seq + 1,
                                                      seq=syn_ack_response.ack)
        send(ack_packet)

        data_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=ack_packet.seq,
                                                       ack=ack_packet.ack) / "Hello, Server!"
        send(data_packet)

        packet_features.append([src_ip, dst_ip, src_port, dst_port])

# Create a DataFrame from the list of features
df = pd.DataFrame(packet_features, columns=[
                  'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])

# Save the DataFrame to a CSV file
output_file = "D:\IIT BHU Intership\CSV Files\csv11.csv"

# Create the CSV file
with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["src_ip", "dst_ip",
                     "dst_ip", "dst_port"])

print("CSV file created successfully!")

# Write the features to the CSV file
df.to_csv(output_file, mode='a', header=False, index=False)

print("Features written to CSV file.")
