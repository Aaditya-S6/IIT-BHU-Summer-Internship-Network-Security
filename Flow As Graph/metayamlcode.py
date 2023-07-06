import yaml

data = {
    'dataset_name': 'mini_multi_dataset',
    'edge_data': [
        {'file_name': 'edges.csv'}
    ],
    'node_data': [
        {'file_name': 'nodes.csv'}
    ],
    'graph_data': {
        'file_name': 'graphs.csv'
    }
}

# Specify the file path where you want to save the YAML file
file_path = "C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\mini_multi_dataset\meta.yaml"

# Write the data to the YAML file
with open(file_path, 'w') as file:
    yaml.dump(data, file)
print("done")
