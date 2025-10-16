#!/bin/bash

# Go-Auth Demo Setup Script

echo "🚀 Setting up Go-Auth Demo..."

# Check if we're in the demo directory
if [ ! -f "package.json" ]; then
    echo "❌ Please run this script from the demo directory"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Check if installation was successful
if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully!"
    echo ""
    echo "🎉 Setup complete! You can now start the demo:"
    echo "   npm run dev"
    echo ""
    echo "📝 Don't forget to:"
    echo "   1. Start your Go-Auth server on localhost:8080"
    echo "   2. Update src/config/demo-config.ts if needed"
    echo "   3. Open http://localhost:3000 in your browser"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi






