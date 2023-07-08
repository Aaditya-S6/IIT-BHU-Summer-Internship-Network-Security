import csv

def get_column_data_type(csv_file, column_name):
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        
        # Find the column index based on the column name
        column_index = reader.fieldnames.index(column_name)
        
        # Iterate over the rows and extract the values in the column
        values = [row[column_name] for row in reader]
        
        # Infer the data type of the values
        data_types = set(type(value) for value in values)
        
        # Return the data types found
        return data_types

# Specify the CSV file path and the column name to check
csv_file = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\train.csv"
column_name = 'edge_index (sequence)'

# Get the data types of values in the specified column
data_types = get_column_data_type(csv_file, column_name)

# Print the data types
print(data_types)
