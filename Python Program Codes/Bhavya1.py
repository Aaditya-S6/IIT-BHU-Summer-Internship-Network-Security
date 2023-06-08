from scapy.all import *

# Read the pcap file or capture packets using sniff() as per your requirements
packets = rdpcap("D:\IIT BHU Intership\ssss\BACnet-1.pcap")


def hex_to_binary(hex_string):
    decimal_value = int(hex_string, 16)
    binary_string = bin(decimal_value)[2:]  
    return binary_string.zfill(len(hex_string) * 4)


# Iterate over packets and extract UDP payloads
for packet in packets:
    if UDP in packet:
        udp_payload = packet[UDP].payload.load
        # Process the extracted payload as needed
        # Example: Print the hexadecimal representation of the payload
        Str=str(udp_payload.hex())
        break;
S=slice(4)
print(Str[S])
print(hex_to_binary(Str[S]))



