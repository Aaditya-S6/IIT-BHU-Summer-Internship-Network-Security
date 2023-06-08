import csv
import numpy as np
from scapy.all import *
from scipy.stats import skew, kurtosis

# Define the desired flow-level features
desired_features = [
    "PacketLength", "MeanPacketLength", "StdDevPacketLength", "AvgAbsDevPacketLength",
    "SkewnessPacketLength", "KurtosisPacketLength", "P10PacketLength", "P20PacketLength", "P30PacketLength",
    "P40PacketLength", "P50PacketLength", "P60PacketLength", "P70PacketLength", "P80PacketLength",
    "P90PacketLength", "MinArrivalTime", "MaxArrivalTime", "MeanArrivalTime", "StdDevArrivalTime",
    "AvgAbsDevArrivalTime", "SkewnessArrivalTime", "KurtosisArrivalTime", "P10ArrivalTime", "P20ArrivalTime",
    "P30ArrivalTime", "P40ArrivalTime", "P50ArrivalTime", "P60ArrivalTime", "P70ArrivalTime", "P80ArrivalTime",
    "P90ArrivalTime", "TotalPackets", "TotalBytes", "TotalPayloadBytes", "FlowDuration"
]


def extract_packet_features(packet):
    packet_features = []

    # Extract the necessary information from the packet
    if packet.haslayer(IP):
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)

        if packet.haslayer(TCP):
            sport = str(packet[TCP].sport)
            dport = str(packet[TCP].dport)
        elif packet.haslayer(UDP):
            sport = str(packet[UDP].sport)
            dport = str(packet[UDP].dport)
        else:
            sport = '0'
            dport = '0'

        # Calculate the packet-level features
        packet_length = len(packet)
        arrival_time = packet.time

        # Add the packet-level features to the list
        features = [
            packet_length,
            np.mean(packet_length),
            np.std(packet_length),
            np.abs(np.mean(packet_length)),
            skew(packet_length + np.finfo(float).eps),  # Add small offset to avoid precision loss
            kurtosis(packet_length + np.finfo(float).eps),  # Add small offset to avoid precision loss
            np.percentile(packet_length, 10),
            np.percentile(packet_length, 20),
            np.percentile(packet_length, 30),
            np.percentile(packet_length, 40),
            np.percentile(packet_length, 50),
            np.percentile(packet_length, 60),
            np.percentile(packet_length, 70),
            np.percentile(packet_length, 80),
            np.percentile(packet_length, 90),
            min(arrival_time),
            max(arrival_time),
            np.mean(arrival_time),
            np.std(arrival_time),
            np.abs(np.mean(arrival_time)),
            skew(arrival_time + np.finfo(float).eps),  # Add small offset to avoid precision loss
            kurtosis(arrival_time + np.finfo(float).eps),  # Add small offset to avoid precision loss
            np.percentile(arrival_time, 10),
            np.percentile(arrival_time, 20),
            np.percentile(arrival_time, 30),
            np.percentile(arrival_time, 40),
            np.percentile(arrival_time, 50),
            np.percentile(arrival_time, 60),
            np.percentile(arrival_time, 70),
            np.percentile(arrival_time, 80),
            np.percentile(arrival_time, 90)
        ]

        packet_features.extend(features)

    return packet_features


def extract_flow_features(pcap_file):
    flow_features = []

    # Open the pcap file
    packets = rdpcap(pcap_file)

    # Create a dictionary to store packet lists for each flow
    flow_packets = {}

    # Iterate over the packets and group them by flows
    for packet in packets:
        if packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)

            if packet.haslayer(TCP):
                sport = str(packet[TCP].sport)
                dport = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                sport = str(packet[UDP].sport)
                dport = str(packet[UDP].dport)
            else:
                sport = '0'
                dport = '0'

            flow_key = (src_ip, dst_ip, sport, dport)

            if flow_key not in flow_packets:
                flow_packets[flow_key] = []

            flow_packets[flow_key].append(packet)

    # Extract flow-level features from the packet lists
    for flow_key, packets in flow_packets.items():
        flow_feature = []

        # Extract the necessary information from the flow
        src_ip, dst_ip, sport, dport = flow_key
        packet_lengths = [len(packet) for packet in packets]
        arrival_times = [packet.time for packet in packets]
        total_packets = len(packets)
        total_bytes = sum(packet_lengths)
        total_payload_bytes = sum([packet.getlayer(IP).len - packet.getlayer(IP).ihl * 4 for packet in packets])
        flow_duration = max(arrival_times) - min(arrival_times)

        # Add the flow-level features to the list
        features = [
            packet_lengths,
            np.mean(packet_lengths),
            np.std(packet_lengths),
            np.abs(np.mean(packet_lengths)),
            skew(packet_lengths + np.finfo(float).eps),  # Add small offset to avoid precision loss
            kurtosis(packet_lengths + np.finfo(float).eps),  # Add small offset to avoid precision loss
            np.percentile(packet_lengths, 10),
            np.percentile(packet_lengths, 20),
            np.percentile(packet_lengths, 30),
            np.percentile(packet_lengths, 40),
            np.percentile(packet_lengths, 50),
            np.percentile(packet_lengths, 60),
            np.percentile(packet_lengths, 70),
            np.percentile(packet_lengths, 80),
            np.percentile(packet_lengths, 90),
            arrival_times,
            min(arrival_times),
            max(arrival_times),
            np.mean(arrival_times),
            np.std(arrival_times),
            np.abs(np.mean(arrival_times)),
            skew(arrival_times + np.finfo(float).eps),  # Add small offset to avoid precision loss
            kurtosis(arrival_times + np.finfo(float).eps),  # Add small offset to avoid precision loss
            np.percentile(arrival_times, 10),
            np.percentile(arrival_times, 20),
            np.percentile(arrival_times, 30),
            np.percentile(arrival_times, 40),
            np.percentile(arrival_times, 50),
            np.percentile(arrival_times, 60),
            np.percentile(arrival_times, 70),
            np.percentile(arrival_times, 80),
            np.percentile(arrival_times, 90),
            total_packets,
            total_bytes,
            total_payload_bytes,
            flow_duration
        ]

        flow_feature.extend(features)
        flow_features.append(flow_feature)

    return flow_features


def write_to_csv(flow_features, output_file):
    # Write the flow features to a CSV file
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(desired_features)
        writer.writerows(flow_features)


def main():
    pcap_file = "D:\IIT BHU Intership\Dataset\Mobile_Applications_Traffic (1)\Mobile_Applications_Traffic\youtube-20230531T093352Z-001\youtube\youtube 4.pcap"
    output_file = "D:\IIT BHU Intership\CSV Files\csv4.csv"

    # Extract flow-level features from the pcap file
    flow_features = extract_flow_features(pcap_file)

    # Write the flow features to a CSV file
    write_to_csv(flow_features, output_file)


if __name__ == '__main__':
    main()
