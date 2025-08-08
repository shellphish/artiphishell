#!/bin/bash

# Display a prompt for the user
echo "Which corpus would you like to use?"
echo "1. OSS-Fuzz corpus"
echo "2. Artiphishell corpus"
read -p "Enter your choice (1 or 2): " corpus_choice

# Process the user's choice
case $corpus_choice in
  1)
    echo "Running OSS-Fuzz corpus script..."
    ./oss-fuzz-corpus.sh
    ;;
  2)
    echo "Running Artiphishell corpus script..."
    ./artiphishell-corpus.sh
    ;;
  *)
    echo "Invalid choice. Please run the script again and select either 1 or 2."
    exit 1
    ;;
esac

echo "Script execution completed."