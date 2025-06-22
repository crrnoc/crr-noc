#!/bin/bash

# Create virtual environment in .venv folder
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Run the Node server
node server.js

