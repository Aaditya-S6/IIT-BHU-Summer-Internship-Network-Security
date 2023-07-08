import json
import random
import math

def split_json_data(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    random.shuffle(data)
    
    total_samples = len(data)
    train_samples = math.ceil(total_samples * 0.6)
    validate_samples = math.ceil(total_samples * 0.2)
    test_samples = total_samples - train_samples - validate_samples
    
    train_data = data[:train_samples]
    validate_data = data[train_samples:train_samples+validate_samples]
    test_data = data[train_samples+validate_samples:]
    
    # Writing train data to file
    with open('train.json', 'w') as file:
        json.dump(train_data, file, indent=4)
    
    # Writing validate data to file
    with open('validate.json', 'w') as file:
        json.dump(validate_data, file, indent=4)
    
    # Writing test data to file
    with open('test.json', 'w') as file:
        json.dump(test_data, file, indent=4)
    
    print("JSON data split into train, validate, and test datasets successfully!")

# Example usage
json_file_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\graphs.json"  # Replace with the path to your JSON file
split_json_data(json_file_path)
