import csv

def convert_data_to_MUTAG_format(data):
    adjacency_matrix = []
    graph_indicator = []
    graph_labels = []
    node_labels = []
    node_id_mapping = {}
    graph_id = 1
    node_id = 1

    for row in data:
        graph_label = row[0]
        edge_label = row[1]
        node_label = row[2]

        # Add edge to adjacency matrix
        adjacency_matrix.append((node_id, node_id+1))

        # Assign graph_id to nodes
        graph_indicator.append(graph_id)
        graph_id += 1

        # Add graph label
        if graph_label not in graph_labels:
            graph_labels.append(graph_label)

        # Add node label
        node_labels.append(node_label)
        
        node_id += 1

    # Write adjacency matrix to DS_A.txt
    with open('DS_A.txt', 'w') as file:
        writer = csv.writer(file, delimiter=',')
        for edge in adjacency_matrix:
            writer.writerow(edge)

    # Write graph indicator to DS_graph_indicator.txt
    with open('DS_graph_indicator.txt', 'w') as file:
        writer = csv.writer(file, delimiter=',')
        for indicator in graph_indicator:
            writer.writerow([indicator])

    # Write graph labels to DS_graph_labels.txt
    with open('DS_graph_labels.txt', 'w') as file:
        writer = csv.writer(file, delimiter=',')
        for label in graph_labels:
            writer.writerow([label])

    # Write node labels to DS_node_labels.txt
    with open('DS_node_labels.txt', 'w') as file:
        writer = csv.writer(file, delimiter=',')
        for label in node_labels:
            writer.writerow([label])

# Example usage with your data
data = [
    ["imgur", 21.0, "108.159.65.191:443"],
    ["imgur", 18.0, "23.213.0.192:443"],
    ["imgur", 18.0, "10.215.173.2:53"],
    ["imgur", 18.0, "10.215.173.2:53"],
    ["imgur", 27.0, "31.13.79.35:443"],
    ["imgur", 27.0, "151.101.129.208:443"],
    ["imgur", 18.0, "151.101.129.208:443"],
    ["imgur", 33.0, "34.149.232.213:443"],
    ["imgur", 15.0, "151.101.129.208:443"],
    ["imgur", 15.0, "151.101.129.208:443"],
    ["imgur", 21.0, "157.240.16.16:443"],
]

convert_data_to_MUTAG_format(data)
