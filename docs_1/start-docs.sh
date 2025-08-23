#!/bin/bash

# GoAuth Documentation Start Script
# This script starts the Docusaurus documentation server

echo "🚀 Starting GoAuth Documentation Server..."
echo "📚 Documentation will be available at: http://localhost:3000"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18.0 or above."
    echo "   Visit: https://nodejs.org/"
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18.0 or above is required. Current version: $(node -v)"
    echo "   Please upgrade Node.js from: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm."
    exit 1
fi

echo "✅ npm version: $(npm -v)"

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ Failed to install dependencies."
        exit 1
    fi
    echo "✅ Dependencies installed successfully."
else
    echo "✅ Dependencies already installed."
fi

# Check if .env file exists
if [ ! -f ".env.local" ]; then
    echo "📝 Creating .env.local file..."
    cat > .env.local << EOF
# GoAuth Documentation Environment Variables
# Add your configuration here if needed

# Example:
# GATSBY_ALGOLIA_APP_ID=your-algolia-app-id
# GATSBY_ALGOLIA_SEARCH_KEY=your-algolia-search-key
# GATSBY_ALGOLIA_ADMIN_KEY=your-algolia-admin-key
EOF
    echo "✅ .env.local file created."
fi

echo ""
echo "🌐 Starting development server..."
echo "📖 Documentation will open in your browser automatically."
echo "🔄 Changes to documentation files will reload automatically."
echo "⏹️  Press Ctrl+C to stop the server."
echo ""

# Start the development server
npm start 