import pyshark

def create_bidirectional_bacnet_flows(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter='bacnet')

    flows = {}

    for packet in capture:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet.udp.srcport
        dst_port = packet.udp.dstport
        seq = int(packet.bacnet.apdu.invoke_id)
        data = packet.bacnet.apdu.data

        # Create a unique key for the flow
        flow_key = f'{src_ip}:{src_port}-{dst_ip}:{dst_port}'

        # Check if the flow exists, if not, create a new one
        if flow_key not in flows:
            flows[flow_key] = {'src_data': b'', 'dst_data': b'', 'seq': seq}

        # Determine the direction of the packet
        direction = 'src' if src_ip == flows[flow_key]['src_ip'] else 'dst'

        # Append the packet data to the corresponding flow direction
        if seq >= flows[flow_key]['seq']:
            flows[flow_key][f'{direction}_data'] += bytes.fromhex(data)
            flows[flow_key]['seq'] = seq + 1

    capture.close()

    return flows


def save_bacnet_flows(flows):
    for flow_key, flow in flows.items():
        src_file = f'{flow_key}_src.bin'
        dst_file = f'{flow_key}_dst.bin'

        with open(src_file, 'wb') as f:
            f.write(flow['src_data'])

        with open(dst_file, 'wb') as f:
            f.write(flow['dst_data'])

        print(f'Saved bidirectional BACnet flow: {src_file}, {dst_file}')


# Provide the path to your pcap file
pcap_file = "D:\IIT BHU Intership\CSV Files\BACnet-1.pcap"

# Create bidirectional BACnet flows
bacnet_flows = create_bidirectional_bacnet_flows(pcap_file)

# Save BACnet flows to separate files
save_bacnet_flows(bacnet_flows)
