import networkx as nx

def create_graph_from_file(file_path):
    # Read the file
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    # Create a new graph
    graph = nx.Graph()
    
    # Extract the file name for the graph label
    file_name = file_path.split('/')[-1].split('.')[0]
    
    # Iterate over the lines and add nodes and attributes to the graph
    for line in lines:
        # Split the line into columns
        columns = line.strip().split(',')
        
        if len(columns) >= 3:
            app_name = columns[0]
            payload_ratio = columns[1]
            socket = columns[2]
            
            # Add the socket as a node to the graph
            graph.add_node(socket, payload_ratio=payload_ratio)
            
    # Set the graph label
    graph.graph['label'] = file_name
    
    return graph

# Example usage
file_path = "C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\App as Graph\CsvFolder\imgur"  # Replace with the path to your text file
graph = create_graph_from_file(file_path)

# Print the graph information
print(f"Graph label: {graph.graph['label']}")
print(f"Number of nodes: {graph.number_of_nodes()}")
print(f"Number of edges: {graph.number_of_edges()}")
nx.draw(graph)
