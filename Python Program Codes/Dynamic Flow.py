from scapy.all import *

pcap_file ="E:\CapturedPackets1.pcap"

packets = rdpcap(pcap_file)

stream_counter = 0

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
        stream_counter += 1

    elif IP in packet and UDP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Source Port:", src_port)
        print("Destination Port:", dst_port)
        
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Hello, Server!"
        
        send(udp_packet)
        

        

print("Number of Streams:", stream_counter)
