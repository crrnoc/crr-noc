#!/bin/bash

echo "🐍 Setting up virtual environment..."

# Create venv only if it doesn't exist
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# Activate it
source .venv/bin/activate

# Install packages only if not already installed
pip install --no-cache-dir -r requirements.txt

echo "🚀 Starting Node server..."
node server.js
