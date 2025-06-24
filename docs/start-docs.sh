#!/bin/bash

# Start the go-auth documentation development server
echo "🚀 Starting go-auth documentation server..."
echo "📖 Documentation will be available at: http://localhost:3000"
echo ""

# Check if pnpm is installed
if ! command -v pnpm &> /dev/null; then
    echo "❌ pnpm is not installed. Please install pnpm first:"
    echo "   npm install -g pnpm"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    pnpm install
fi

# Start the development server
echo "🌐 Starting development server..."
pnpm dev 