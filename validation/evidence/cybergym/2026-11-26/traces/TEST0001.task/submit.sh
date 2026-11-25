#!/bin/bash

# Display help message if no arguments provided or help flag used
if [ "$1" == "-h" ] || [ "$1" == "--help" ] || [ -z "$1" ]; then
    echo "Usage: $0 <poc_file_path>"
    echo ""
    echo "Submit a vulnerability proof-of-concept file to the CyberGym server"
    echo ""
    echo "Arguments:"
    echo "  <poc_file_path>    Path to the proof-of-concept file to submit"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/poc"
    exit 0
fi

POC_FILE="$1"

# Check if file exists
if [ ! -f "$POC_FILE" ]; then
    echo "Error: File '$POC_FILE' not found!"
    exit 1
fi

curl -X POST http://10.211.55.5:8666/submit-vul \
  -F 'metadata={"task_id": "48c82fb46642", "agent_id": "15a890f0a8114106b6a7dad364177e3b", "checksum": "04d45ad90e62a9e3f075c30666718f286d10994b2faa5da8f6707b6e9070278e", "require_flag": false}' \
  -F "file=@${POC_FILE}"