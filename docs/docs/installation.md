---
id: installation
title: Installation
sidebar_label: Installation
sidebar_position: 2
---

# Installation

This guide will help you install and set up GoAuth in your Go project.

## Prerequisites

Before installing GoAuth, make sure you have:

- **Go 1.21+** installed on your system
- A Go module initialized in your project
- Access to the required dependencies

## Quick Installation

### 1. Add GoAuth to your project

```bash
go get github.com/your-org/goauth
```

### 2. Import in your code

```go
import "github.com/your-org/goauth"
```

## Detailed Installation Steps

### Step 1: Initialize Go Module

If you haven't already initialized a Go module in your project:

```bash
go mod init your-project-name
```

### Step 2: Install Dependencies

Install GoAuth and its dependencies:

```bash
go get github.com/your-org/goauth
go get github.com/your-org/goauth/pkg/auth
go get github.com/your-org/goauth/pkg/config
```

### Step 3: Verify Installation

Create a simple test file to verify the installation:

```go
package main

import (
    "fmt"
    "github.com/your-org/goauth"
)

func main() {
    fmt.Println("GoAuth version:", goauth.Version)
}
```

Run the test:

```bash
go run main.go
```

## Configuration

After installation, you'll need to configure GoAuth for your specific use case. See the [Configuration Guide](configuration/auth.md) for detailed setup instructions.

## Dependencies

GoAuth has the following main dependencies:

- **Database**: PostgreSQL, MySQL, or custom implementations
- **Cache**: Redis (optional, for session storage)
- **Email**: SMTP or custom email providers
- **SMS**: Twilio, AWS SNS, or custom SMS providers

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure your Go version is 1.21 or higher
2. **Module not found**: Run `go mod tidy` to clean up dependencies
3. **Version conflicts**: Check for conflicting dependency versions

### Getting Help

If you encounter issues during installation:

- Check the [GitHub Issues](https://github.com/your-org/goauth/issues)
- Review the [Configuration Guide](configuration/auth.md)
- Join our [Discussions](https://github.com/your-org/goauth/discussions)

## Next Steps

Once you have GoAuth installed, proceed to:

- [Quick Start Guide](quickstart.md) - Get up and running quickly
- [Configuration Guide](configuration/auth.md) - Configure GoAuth for your needs
- [Basic Authentication](getting-started/basic-auth.md) - Implement basic authentication
