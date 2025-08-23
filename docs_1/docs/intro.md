---
id: intro
title: Introduction
sidebar_label: Introduction
slug: /
---

# Welcome to GoAuth

GoAuth is a comprehensive, production-ready authentication library for Go applications. It provides a robust foundation for implementing secure authentication systems with support for multiple authentication methods, frameworks, and security features.

## What is GoAuth?

GoAuth is designed to simplify the implementation of authentication in Go applications while maintaining high security standards. It abstracts away the complexity of authentication protocols and provides a clean, consistent API across different authentication methods.

## Key Features

- **Multiple Authentication Methods**: OAuth 2.0, JWT, Magic Links, Two-Factor Authentication
- **Framework Support**: Native support for popular Go web frameworks
- **Security Features**: Rate limiting, CSRF protection, reCAPTCHA integration
- **Flexible Storage**: Support for multiple database backends
- **Production Ready**: Built with security and scalability in mind

## Why Choose GoAuth?

- **Security First**: Implements industry best practices for authentication security
- **Easy Integration**: Simple API that integrates seamlessly with existing Go applications
- **Extensible**: Modular design allows for custom implementations and extensions
- **Well Documented**: Comprehensive documentation and examples
- **Active Development**: Regular updates and community support

## Quick Example

```go
package main

import (
    "github.com/your-org/goauth"
    "github.com/gin-gonic/gin"
)

func main() {
    // Initialize GoAuth
    auth := goauth.New()

    // Setup routes
    r := gin.Default()

    // Register authentication endpoints
    auth.SetupRoutes(r)

    r.Run(":8080")
}
```

## Getting Started

Ready to get started? Check out our [Installation Guide](installation.md) and [Quick Start Tutorial](quickstart.md) to begin building secure authentication into your Go applications.

## Support

- **Documentation**: This site contains comprehensive guides and API references
- **GitHub**: [github.com/your-org/goauth](https://github.com/your-org/goauth)
- **Issues**: Report bugs and request features on GitHub
- **Discussions**: Join the community discussion on GitHub
