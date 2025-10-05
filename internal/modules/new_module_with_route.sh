#!/bin/bash

# Check if folder name is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <folder-name>"
  exit 1
fi

FOLDER=$1

# Create main folder
mkdir -p "$FOLDER"

# Navigate into the folder
cd "$FOLDER" || exit

# Create file
touch module.go

# Create directories
mkdir -p models repositories services handlers tests middlewares

echo "Project structure created successfully in '$FOLDER'"
