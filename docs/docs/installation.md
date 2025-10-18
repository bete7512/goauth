---
id: installation
title: Installation
sidebar_label: Installation
sidebar_position: 2
---

# Installation

Get GoAuth installed and ready to use in your Go project.

## Prerequisites

- **Go 1.21+** installed on your system
- A Go module initialized in your project (`go mod init`)
- Basic knowledge of Go

## Quick Installation

### Step 1: Install GoAuth

```bash
go get github.com/bete7512/goauth
```

That's it! GoAuth and its dependencies will be automatically installed.

### Step 2: Verify Installation

Create a test file to verify:

```go
package main

import (
    "fmt"
    "github.com/bete7512/goauth/pkg/auth"
)

func main() {
    fmt.Println("GoAuth installed successfully!")
}
```

Run it:

```bash
go run main.go
```

## Database Setup

GoAuth requires a database. Choose one:

### Option 1: SQLite (Development)

No setup required! Perfect for development and testing:

```go
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "sqlite",
    DSN:     "auth.db",
})
```

### Option 2: PostgreSQL (Recommended for Production)

**Install PostgreSQL:**
- macOS: `brew install postgresql`
- Ubuntu: `sudo apt-get install postgresql`
- Windows: Download from [postgresql.org](https://www.postgresql.org/download/)

**Create Database:**
```sql
CREATE DATABASE authdb;
CREATE USER authuser WITH PASSWORD 'securepassword';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
```

**Use in GoAuth:**
```go
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "postgres",
    DSN:     "host=localhost user=authuser password=securepassword dbname=authdb sslmode=disable",
})
```

### Option 3: MySQL

**Install MySQL:**
- macOS: `brew install mysql`
- Ubuntu: `sudo apt-get install mysql-server`
- Windows: Download from [mysql.com](https://www.mysql.com/downloads/)

**Create Database:**
```sql
CREATE DATABASE authdb;
CREATE USER 'authuser'@'localhost' IDENTIFIED BY 'securepassword';
GRANT ALL PRIVILEGES ON authdb.* TO 'authuser'@'localhost';
```

**Use in GoAuth:**
```go
store, _ := storage.NewStorage(config.StorageConfig{
    Driver:  "gorm",
    Dialect: "mysql",
    DSN:     "authuser:securepassword@tcp(localhost:3306)/authdb?parseTime=true",
})
```

## Optional Dependencies

Install these only if you need specific modules:

### For Email (Notification Module)

No additional installation needed. Configure with your email provider:

```go
// SendGrid
import "github.com/bete7512/goauth/internal/modules/notification/services/senders"

emailSender := senders.NewSendGridEmailSender(&senders.SendGridConfig{
    APIKey: "your-sendgrid-api-key",
})

// SMTP (Gmail, etc.)
emailSender := senders.NewSMTPEmailSender(&senders.SMTPConfig{
    Host:     "smtp.gmail.com",
    Port:     587,
    Username: "your-email@gmail.com",
    Password: "your-app-password",
})
```

### For SMS (Notification Module)

```go
// Twilio
smsSender := senders.NewTwilioSMSSender(&senders.TwilioConfig{
    AccountSID: "your-account-sid",
    AuthToken:  "your-auth-token",
    FromNumber: "+1234567890",
})
```

## Project Structure

Recommended project structure:

```
your-project/
├── main.go                  # Application entry point
├── go.mod                   # Go modules file
├── go.sum                   # Dependencies checksum
├── .env                     # Environment variables (don't commit!)
└── README.md               # Project documentation
```

## Environment Variables

Create a `.env` file (optional but recommended):

```env
# Database
DATABASE_URL=postgres://user:pass@localhost/authdb?sslmode=disable

# Security
JWT_SECRET_KEY=your-secret-key-min-32-characters!!
ENCRYPTION_KEY=your-encryption-key-32-characters!

# Email (if using notification module)
SENDGRID_API_KEY=your-sendgrid-api-key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# SMS (if using notification module)
TWILIO_ACCOUNT_SID=your-account-sid
TWILIO_AUTH_TOKEN=your-auth-token
TWILIO_FROM_NUMBER=+1234567890

# Application
PORT=8080
FRONTEND_URL=http://localhost:3000
```

**Load environment variables:**

```bash
go get github.com/joho/godotenv
```

```go
import "github.com/joho/godotenv"

func main() {
    // Load .env file
    godotenv.Load()
    
    // Use environment variables
    jwtSecret := os.Getenv("JWT_SECRET_KEY")
}
```

## Minimal Example

After installation, create a minimal working example:

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/bete7512/goauth/internal/storage"
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/bete7512/goauth/pkg/config"
    "github.com/bete7512/goauth/pkg/types"
)

func main() {
    // Storage
    store, _ := storage.NewStorage(config.StorageConfig{
        Driver:  "gorm",
        Dialect: "sqlite",
        DSN:     "auth.db",
    })
    defer store.Close()

    // Auth
    a, _ := auth.New(&config.Config{
        Storage:     store,
        AutoMigrate: true,
        Security: types.SecurityConfig{
            JwtSecretKey:  "your-secret-key-min-32-chars!!!!",
            EncryptionKey: "your-encryption-key-32-chars!",
        },
    })
    defer a.Close()

    // Initialize
    a.Initialize(context.Background())

    // Serve
    mux := http.NewServeMux()
    for _, route := range a.Routes() {
        mux.Handle(route.Path, route.Handler)
    }

    log.Println("Server running on :8080")
    http.ListenAndServe(":8080", mux)
}
```

## Troubleshooting

### Common Installation Issues

**1. Module Not Found**
```
Error: cannot find module providing package github.com/bete7512/goauth
```

**Solution:**
```bash
go mod tidy
go get github.com/bete7512/goauth
```

**2. Go Version Too Old**
```
Error: package github.com/bete7512/goauth requires go version 1.21+
```

**Solution:**
- Update Go to 1.21 or higher
- Check version: `go version`

**3. Database Driver Not Found**
```
Error: sql: unknown driver "postgres"
```

**Solution:**
GoAuth automatically includes GORM drivers. If you still see this:
```bash
go get -u gorm.io/driver/postgres
go get -u gorm.io/driver/mysql
go get -u gorm.io/driver/sqlite
```

**4. Import Errors**
```
Error: package github.com/bete7512/goauth/pkg/auth is not in GOROOT
```

**Solution:**
```bash
go mod download
go mod tidy
```

### Platform-Specific Issues

**Windows:**
- Use Git Bash or PowerShell for commands
- Ensure Go is in your PATH
- Use forward slashes in paths

**macOS:**
- Xcode Command Line Tools may be required
- Install with: `xcode-select --install`

**Linux:**
- Ensure gcc is installed for SQLite
- Ubuntu/Debian: `sudo apt-get install build-essential`

## Updating GoAuth

To update to the latest version:

```bash
go get -u github.com/bete7512/goauth
go mod tidy
```

Check for breaking changes in the [release notes](https://github.com/bete7512/goauth/releases).

## IDE Setup

### VS Code

Install recommended extensions:
- Go extension by Google
- REST Client for testing APIs

Add to `.vscode/settings.json`:
```json
{
  "go.useLanguageServer": true,
  "go.lintOnSave": "package",
  "go.formatTool": "goimports"
}
```

### GoLand

GoLand has built-in Go support. Just open your project and it will configure automatically.

## Next Steps

Now that GoAuth is installed:

1. **[Quick Start Guide](quickstart.md)** - Build your first auth system
2. **[Core Module Documentation](modules/core.md)** - Learn about core features
3. **[Configuration Guide](configuration/auth.md)** - Configure GoAuth for your needs

## Getting Help

If you encounter issues:

- 📖 Check this documentation
- 🔍 Search [GitHub Issues](https://github.com/bete7512/goauth/issues)
- 💬 Ask in [GitHub Discussions](https://github.com/bete7512/goauth/discussions)
- 🐛 Report bugs via [GitHub Issues](https://github.com/bete7512/goauth/issues/new)

---

**Ready to build?** → [Quick Start Tutorial](quickstart.md)
