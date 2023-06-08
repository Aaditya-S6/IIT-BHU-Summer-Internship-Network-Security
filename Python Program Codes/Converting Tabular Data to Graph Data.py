import pandas as pd
import networkx as nx
from scapy.all import *

# Load the tabular dataset from CSV
dataset_path = "E:\CSV6.csv"
df = pd.read_csv(dataset_path)

# Create an empty NetworkX graph
graph = nx.Graph()

# Convert the tabular dataset to a graph dataset
def convert_to_graph_dataset(df):
    for index, row in df.iterrows():
        # Example: Assuming the dataset has 'Packet Length' and 'Min Packet Length' columns for edges
        packet_length = row['Packet Length']
        min_packet_length = row['Min Packet Length']

        # Add an edge between packet_length and min_packet_length in the graph
        graph.add_edge(packet_length, min_packet_length)

    # Convert the NetworkX graph to a Scapy PacketList object
    packets = graph_to_packets(graph)

    # Convert the Scapy PacketList object to a graph dataset
    graph_dataset = packets_to_graph_dataset(packets)

    return graph_dataset

def graph_to_packets(graph):
    packets = []
    for packet_length, min_packet_length in graph.edges():
        # Create a basic IP packet with packet_length and min_packet_length
        packet = IP(len=packet_length) / IP(len=min_packet_length)
        packets.append(packet)

    return packets

def packets_to_graph_dataset(packets):
    # Convert the Scapy PacketList to a Pandas DataFrame
    df = pd.DataFrame(packets_to_dict(packets))

    # Convert the Pandas DataFrame to a graph dataset format suitable for GNNs
    # Example: Assuming the dataset has 'Packet Length' and 'Min Packet Length' columns for node features
    x = df[['Packet Length', 'Min Packet Length']].values
    y = None  # Adjust this based on your label column

    # Create a dictionary to store the graph dataset
    graph_dataset = {
        'x': x,  # Node features
        'y': y,  # Node labels
        'edge_index': None,  # Edge indices (if needed)
    }

    return graph_dataset

# Convert the tabular dataset to a graph dataset
graph_dataset = convert_to_graph_dataset(df)

# Print the converted graph dataset
print(graph_dataset)
