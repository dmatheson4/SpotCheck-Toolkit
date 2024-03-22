import os
import sys


def read_lines_from_files(directory_path):
    """
    Reads lines from all files within a directory and its subdirectories.

    Args:
    directory_path (str): Path to the directory containing files.

    Returns:
    dict: Dictionary with file paths as keys and lists of lines as values.
    """
    lines_by_file = {}
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if os.path.isfile(file_path):
                with open(file_path, "r") as file:
                    lines_by_file[file_path] = file.readlines()
    return lines_by_file


def load_files(directory_path):
    """
    Main function to load lines from files within a directory and its subdirectories.

    Args:
    directory_path (str): Path to the directory containing files.
    """
    lines_by_file = read_lines_from_files(directory_path)

    # Print or process lines from each file
    for file_path, lines in lines_by_file.items():
        print(f"Lines from file: {file_path}")
        for line in lines:
            print(line.strip())  # Stripping newline characters


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <directory_path>")
    else:
        directory_path = sys.argv[1]
        load_files(directory_path)
