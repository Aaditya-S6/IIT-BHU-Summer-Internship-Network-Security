import csv
import random

def shuffle_csv_rows(csv_file):
    with open(csv_file, 'r', newline='') as file:
        reader = csv.reader(file)
        rows = list(reader)  # Read all rows into a list

        header_row = rows[0]
        data_rows = rows[1:]

        random.shuffle(data_rows)  # Shuffle the data rows
    print("done reading")
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header_row)  # Write the header row back to the file
        writer.writerows(data_rows)  # Write the shuffled data rows
    print("Completed")

# Usage example
csv_file_path = "C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\GraphsDataset.csv"  # Replace with the path to your CSV file
shuffle_csv_rows(csv_file_path)
