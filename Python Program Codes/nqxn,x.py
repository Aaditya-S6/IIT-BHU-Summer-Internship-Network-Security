from scapy.all import *

def extract_conversation_length(packet):
    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst

        src_to_dst = 0
        dst_to_src = 0

        if 'TCP' in packet:
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport

            # Calculate conversation length from source to destination
            src_to_dst = len(packet['TCP'].payload)

            # Create a reverse packet for conversation length from destination to source
            reverse_packet = packet.copy()
            reverse_packet['IP'].src = dst_ip
            reverse_packet['IP'].dst = src_ip
            reverse_packet['TCP'].sport = dst_port
            reverse_packet['TCP'].dport = src_port

            if 'Raw' in reverse_packet:
                dst_to_src = len(reverse_packet['TCP'].payload)

        return src_to_dst, dst_to_src

# Example usage
packet = IP(src="192.168.0.1", dst="10.0.0.1") / TCP(sport=1234, dport=5678) / Raw(b"Hello, World!")

src_to_dst_len, dst_to_src_len = extract_conversation_length(packet)

print("Conversation length from source to destination:", src_to_dst_len)
print("Conversation length from destination to source:", dst_to_src_len)
