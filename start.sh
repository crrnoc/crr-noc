#!/bin/bash

echo "📦 Installing Python packages..."
pip install --no-cache-dir -r requirements.txt

echo "🚀 Starting Node server..."
node server.js
