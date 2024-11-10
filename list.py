"""
Find and print files in current directory with .toml or .jl extension
excluding lib folder and Manifest.toml files.
"""

import os

def find_and_print_files(extensions=["toml", "jl"], exclude_paths=["lib", "Manifest.toml"]):
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith(tuple(extensions)):
                # Construct the full file path
                file_path = os.path.join(root, file)

                # Check if the file path matches any excluded path
                exclude = False
                for exclude_path in exclude_paths:
                    if exclude_path in file_path:
                        exclude = True
                        break

                if not exclude:
                    print("===== {} =====".format(file_path))
                    with open(file_path, 'r') as f:
                        print(f.read())

# Example usage:
find_and_print_files()
