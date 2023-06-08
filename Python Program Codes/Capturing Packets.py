from scapy.all import*
packets = sniff(filter="icmp and src host 182.251.115.189", count=5)
for packet in packets:
    print(packet.summary())
