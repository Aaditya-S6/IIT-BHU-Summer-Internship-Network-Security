from scapy.all import *

# Create an ICMP echo request packet
packet = IP(dst="www.example.com")/ICMP()

# Send the packet and receive the response
reply = sr1(packet)

# Display the response
reply.show()
