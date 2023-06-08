from scapy.all import *
import sys
src_ip = sys.argv[1]
dst = sys.argv[2]
src_port = 12345  
dst_port = 80
stream_counter = 0

syn_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
syn_ack_response = sr1(syn_packet, verbose=0)
stream_counter+=1

ack_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A",ack=syn_ack_response.seq + 1 ,
seq=syn_ack_response.ack)
send(ack_packet)

data_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA",seq=ack_packet.seq,
ack=ack_packet.ack) / "Hello, Server!"
send(data_packet)
stream_counter+=1

print("Number of Streams:",stream_counter)
