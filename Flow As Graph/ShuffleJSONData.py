import json
import random

# Read the JSON file
with open("C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\graphs.json", 'r') as file:
    data = json.load(file)

# Shuffle the data
random.shuffle(data)

# Write the shuffled data back to the JSON file
with open("C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\ShuffelGraph.json", 'w') as file:
    json.dump(data, file)
