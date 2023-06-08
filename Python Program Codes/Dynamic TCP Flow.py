from scapy.all import IP, TCP, sr1

# Source and destination port numbers
src_port = 1234
dst_port = 80

# Send SYN packet to initiate TCP handshake
ip_packet = IP(dst="google.com")
tcp_packet = TCP(sport=src_port, dport=dst_port, flags="S")
syn_ack_response = sr1(ip_packet / tcp_packet, verbose=False)

# Extract the destination IP address from the response
dst_ip = syn_ack_response[IP].src

# Send ACK packet to complete TCP handshake
ack_packet = TCP(sport=src_port, dport=dst_port, flags="A", ack=syn_ack_response[TCP].seq + 1)
response = sr1(ip_packet / ack_packet, verbose=False)

# Send additional TCP packets within the established flow
if response:
    data_packet = TCP(sport=src_port, dport=dst_port, flags="PA", seq=response[TCP].ack, ack=response[TCP].seq + 1)
    payload = "Hello, TCP!"
    response = sr1(ip_packet / data_packet / payload, verbose=False)

    # Process the response packet
    if response:
        print(response.show())
