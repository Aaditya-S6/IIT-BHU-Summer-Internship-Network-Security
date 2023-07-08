import json
import random

def shuffle_json_data(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    random.shuffle(data)
    
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)
    
    print("JSON data shuffled successfully!")

# Example usage
json_file_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\graphs.json"  # Replace with the path to your JSON file
shuffle_json_data(json_file_path)
