import csv
import random
import math

def split_csv_data(csv_file, train_file, val_file, test_file, split_ratio=(0.6, 0.2, 0.2), random_seed=None):
    with open(csv_file, 'r', newline='') as file:
        reader = csv.reader(file)
        rows = list(reader)  # Read all rows into a list

        header_row = rows[0]
        data_rows = rows[1:]

        total_rows = len(data_rows)
        train_size = math.floor(split_ratio[0] * total_rows)
        val_size = math.floor(split_ratio[1] * total_rows)

        # Set random seed for consistent splitting
        if random_seed is not None:
            random.seed(random_seed)

        random.shuffle(data_rows)  # Shuffle the data rows

        train_data = data_rows[:train_size]
        val_data = data_rows[train_size:train_size+val_size]
        test_data = data_rows[train_size+val_size:]
    print("read done")

    # Write to separate files
    write_to_csv(train_file, header_row, train_data)
    write_to_csv(val_file, header_row, val_data)
    write_to_csv(test_file, header_row, test_data)

def write_to_csv(file_path, header_row, data_rows):
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header_row)  # Write the header row
        writer.writerows(data_rows)  # Write the data rows


# Usage example
csv_file_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\Shuffled Data.csv"  # Replace with the path to your CSV file
train_file_path = r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\train.csv" # Replace with the desired path for the training file
val_file_path =r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\validation.csv."  # Replace with the desired path for the validation file
test_file_path =r"C:\Github repo\IIT-BHU-Summer-Internship-Network-Security\Flow As Graph\Dataset\test.csv."

split_csv_data(csv_file_path, train_file_path, val_file_path, test_file_path)
print("complete")
