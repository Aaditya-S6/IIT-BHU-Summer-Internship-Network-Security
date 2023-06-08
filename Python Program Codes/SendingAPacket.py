from scapy.all import*
packet=IP(dst="www.google.com")/ICMP()
response=sr1(packet)
print(response.summary())
