#!/bin/bash

# This script recursively find all the files in a directory and run certigo dump cli on each file to extract the each certificate's information

# Define the root directory
ROOT_DIR="INSERT ROOT DIRECTORY HERE"

# Function to recursively process files
process_files() {
  local dir="$1"
  for file in "$dir"/*; do
    if [ -d "$file" ]; then
      # If the file is a directory, recursively process it
      process_files "$file"
    elif [ -f "$file" ]; then
      # If the file is a regular file, run the Go command
      echo "Processing file $file"
      go run main.go dump --format PEM "$file"
      if [ $? -ne 0 ]; then
        echo "Error running command on file $file"
      fi
    fi
  done
}

# Start processing from the root directory
process_files "$ROOT_DIR"