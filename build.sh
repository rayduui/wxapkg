#!/bin/bash

# Exit on error
set -e

echo "Building wxapkg tool for macOS..."

# Ensure Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go before running this script."
    echo "Visit https://golang.org/doc/install for installation instructions."
    exit 1
fi

# Get dependencies
echo "Downloading dependencies..."
go mod download

# Build for macOS
echo "Building for macOS (x86_64)..."
GOOS=darwin GOARCH=amd64 go build -o wxapkg-amd64 .

# Check if Apple Silicon build is needed (on M1/M2 Macs)
if [[ $(uname -m) == 'arm64' ]]; then
    echo "Building for macOS (arm64)..."
    GOOS=darwin GOARCH=arm64 go build -o wxapkg-arm64 .
    
    # Create universal binary if possible
    if command -v lipo &> /dev/null; then
        echo "Creating universal binary..."
        lipo -create -output wxapkg wxapkg-amd64 wxapkg-arm64
        rm wxapkg-amd64 wxapkg-arm64
        chmod +x wxapkg
    else
        # Just use the arm64 binary and rename it
        mv wxapkg-arm64 wxapkg
        rm wxapkg-amd64
        chmod +x wxapkg
    fi
else
    # Just use the amd64 binary and rename it
    mv wxapkg-amd64 wxapkg
    chmod +x wxapkg
fi

echo "Build complete! The wxapkg tool is ready to use."
echo "Run ./wxapkg to get started" 