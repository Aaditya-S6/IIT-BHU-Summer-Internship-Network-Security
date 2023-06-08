import csv

# Path to the pcap file
pcap_file = "E:\CapturedPackets1.pcap"

# Read the pcap file
packets = rdpcap(pcap_file)

# Create dictionaries to store flows and flow-level features
upstream_flows = {}

# Process each packet in the pcap file
for packet in packets:
    if TCP in packet:
        # Get the source IP, destination IP, source port, and destination port
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Create a unique key for the TCP flow
        flow_key = (src_ip, dst_ip, src_port, dst_port)

        # Calculate packet length and intra-packet arrival time
        packet_len = len(packet)
        if 'time' in packet:
            arrival_time = packet.time
        else:
            arrival_time = 0

        # Add the packet length and arrival time to the corresponding flow
        if flow_key in upstream_flows:
            upstream_flows[flow_key]['packet_lens'].append(packet_len)
            upstream_flows[flow_key]['arrival_times'].append(arrival_time)
        else:
            upstream_flows[flow_key] = {'packet_lens': [packet_len], 'arrival_times': [arrival_time]}

# Calculate flow-level features for upstream flows
flow_features = []
for flow_key, flow_data in upstream_flows.items():
    packet_lens = np.array(flow_data['packet_lens'])
    arrival_times = np.array(flow_data['arrival_times'])

    # Calculate flow-level features for packet length
    packet_len_min = np.min(packet_lens)
    packet_len_max = np.max(packet_lens)
    packet_len_mean = np.mean(packet_lens)
    packet_len_std = np.std(packet_lens)
    packet_len_var = np.var(packet_lens)
    packet_len_mad = np.mean(np.abs(packet_lens - packet_len_mean))

    # Check if standard deviation is zero to avoid division by zero
    if packet_len_std != 0:
        packet_len_skew = np.mean(((packet_lens - packet_len_mean) / packet_len_std) ** 3)
        packet_len_kurt = np.mean(((packet_lens - packet_len_mean) / packet_len_std) ** 4)
    else:
        packet_len_skew = 0
        packet_len_kurt = 0

    packet_len_percentiles = np.percentile(packet_lens, range(10, 91, 10))

    # Calculate flow-level features for arrival time
    arrival_time_min = np.min(arrival_times)
    arrival_time_max = np.max(arrival_times)
    arrival_time_mean = np.mean(arrival_times)
    arrival_time_std = np.std(arrival_times)
    arrival_time_var = np.var(arrival_times)
    arrival_time_mad = np.mean(np.abs(arrival_times - arrival_time_mean))

    # Check if standard deviation is zero to avoid division by zero
    if arrival_time_std != 0:
        arrival_time_skew = np.mean(((arrival_times - arrival_time_mean) / arrival_time_std) ** 3)
        arrival_time_kurt = np.mean(((arrival_times - arrival_time_mean) / arrival_time_std) ** 4)
    else:
        arrival_time_skew = 0
        arrival_time_kurt = 0

    arrival_time_percentiles = np.percentile(arrival_times, range(10, 91, 10))

    # Calculate flow-level features for total packets, total bytes, total payload bytes, and flow duration
    total_packets = len(packet_lens)
    total_bytes = np.sum(packet_lens)
    total_payload_bytes = np.sum(packet_lens - 40)  # Assuming 40 bytes for TCP/IP headers
    flow_duration = arrival_times[-1] - arrival_times[0]

    # Create a dictionary of flow-level features
    flow_feature = {
        'Flow Key': flow_key,
        'Packet Length Min': packet_len_min,
        'Packet Length Max': packet_len_max,
        'Packet Length Mean': packet_len_mean,
        'Packet Length Std': packet_len_std,
        'Packet Length Var': packet_len_var,
        'Packet Length MAD': packet_len_mad,
        'Packet Length Skew': packet_len_skew,
        'Packet Length Kurt': packet_len_kurt,
        'Packet Length Percentiles': packet_len_percentiles,
        'Arrival Time Min': arrival_time_min,
        'Arrival Time Max': arrival_time_max,
        'Arrival Time Mean': arrival_time_mean,
        'Arrival Time Std': arrival_time_std,
        'Arrival Time Var': arrival_time_var,
        'Arrival Time MAD': arrival_time_mad,
        'Arrival Time Skew': arrival_time_skew,
        'Arrival Time Kurt': arrival_time_kurt,
        'Arrival Time Percentiles': arrival_time_percentiles,
        'Total Packets': total_packets,
        'Total Bytes': total_bytes,
        'Total Payload Bytes': total_payload_bytes,
        'Flow Duration': flow_duration
    }

    flow_features.append(flow_feature)

# Define the output CSV file path
output_file = "E:\CSV sample.csv"

# Write the flow-level features to the CSV file
with open(output_file, "w", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=flow_features[0].keys())
    writer.writeheader()
    writer.writerows(flow_features)

print("Flow-level features extracted and stored in CSV format.")
