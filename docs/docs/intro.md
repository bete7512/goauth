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

## Quick Example (Modular Architecture)

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
)

func main() {
    // Storage via factory (GORM + SQLite shown)
    store, err := storage.NewStorage(config.StorageConfig{Driver: "gorm", Dialect: "sqlite", DSN: "auth.db", AutoMigrate: true})
    if err != nil { log.Fatal(err) }
    defer store.Close()

    // Auth with security settings
    a, err := auth.New(&config.Config{Storage: store, AutoMigrate: true, Security: config.SecurityConfig{JwtSecretKey: "change-me-32-bytes", EncryptionKey: "change-me-32-bytes"}})
    if err != nil { log.Fatal(err) }

    // Optional: register modules before Initialize (e.g., twofactor, csrf)
    // a.Use(twofactor.New(&twofactor.TwoFactorConfig{...}))

    if err := a.Initialize(context.Background()); err != nil { log.Fatal(err) }

    // Serve with net/http
    mux := http.NewServeMux()
    for _, r := range a.Routes() {
        mux.Handle(r.Path, r.Handler)
    }
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Getting Started

Ready to get started? Check out our [Installation Guide](installation.md) and [Quick Start Tutorial](quickstart.md) to begin building secure authentication into your Go applications.

## Support

- **Documentation**: This site contains comprehensive guides and API references
- **GitHub**: [github.com/your-org/goauth](https://github.com/your-org/goauth)
- **Issues**: Report bugs and request features on GitHub
- **Discussions**: Join the community discussion on GitHub
