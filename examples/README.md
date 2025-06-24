# GoAuth Examples

This directory contains various examples demonstrating how to use the GoAuth library with different frameworks and configurations.

## 📁 Directory Structure

```
examples/
├── basic/              # Basic usage with standard HTTP
├── frameworks/         # Framework-specific examples
│   ├── gin/           # Gin framework integration
│   ├── echo/          # Echo framework integration
│   ├── chi/           # Chi framework integration
│   └── fiber/         # Fiber framework integration
├── oauth/             # OAuth provider examples
└── custom/            # Custom implementations
```

## 🚀 Quick Start

### Basic Example

```bash
cd examples/basic
go run main.go
```

### Gin Framework Example

```bash
cd examples/frameworks/gin
go run main.go
```

## 📚 Available Examples

### 1. Basic Example (`basic/`)
- Standard HTTP server setup
- Manual route registration
- Basic configuration

### 2. Framework Examples (`frameworks/`)
- **Gin**: High-performance HTTP web framework
- **Echo**: High performance HTTP framework
- **Chi**: Lightweight HTTP router
- **Fiber**: Express inspired web framework

### 3. OAuth Examples (`oauth/`)
- Google OAuth integration
- GitHub OAuth integration
- Facebook OAuth integration
- Custom OAuth provider setup

### 4. Custom Examples (`custom/`)
- Custom repository implementations
- Custom middleware examples
- Custom hook implementations

## 🔧 Configuration

All examples use a similar configuration structure. You'll need to:

1. **Database Setup**: Configure your database connection
2. **JWT Secret**: Set a secure JWT secret key
3. **Email/SMS**: Configure notification services (optional)
4. **OAuth Providers**: Add OAuth credentials (if using OAuth)

## 🛠️ Running Examples

### Prerequisites

1. **Database**: PostgreSQL, MySQL, or MongoDB
2. **Go**: Version 1.21 or later
3. **Dependencies**: Run `go mod tidy` in each example directory

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bete7512/goauth.git
   cd goauth
   ```

2. **Navigate to an example**:
   ```bash
   cd examples/basic
   ```

3. **Update configuration**:
   - Edit `main.go` to match your database settings
   - Update JWT secret and other configuration

4. **Run the example**:
   ```bash
   go run main.go
   ```

5. **Test the endpoints**:
   ```bash
   # Register a user
   curl -X POST http://localhost:8080/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"user@example.com","password":"password123"}'
   
   # Login
   curl -X POST http://localhost:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"user@example.com","password":"password123"}'
   ```

## 📖 Framework Integration

### Gin Framework

```go
import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/gin-gonic/gin"
)

// Initialize auth service
authService, _ := auth.NewBuilder().WithConfig(config).Build()

// Setup Gin router
router := gin.Default()

// Register auth routes
authRoutes := authService.GetRoutes()
for _, route := range authRoutes {
    handler := authService.GetWrappedHandler(route)
    ginHandler := gin.WrapF(handler)
    
    switch route.Method {
    case "GET":
        router.GET(route.Path, ginHandler)
    case "POST":
        router.POST(route.Path, ginHandler)
    }
}
```

### Echo Framework

```go
import (
    "github.com/bete7512/goauth/pkg/auth"
    "github.com/labstack/echo/v4"
)

// Initialize auth service
authService, _ := auth.NewBuilder().WithConfig(config).Build()

// Setup Echo
e := echo.New()

// Register auth routes
authRoutes := authService.GetRoutes()
for _, route := range authRoutes {
    handler := authService.GetWrappedHandler(route)
    e.Any(route.Path, echo.WrapHandler(http.HandlerFunc(handler)))
}
```

## 🔒 Security Notes

- **JWT Secret**: Use a strong, random secret key (32+ characters)
- **HTTPS**: Use HTTPS in production
- **Database**: Secure your database connection
- **Environment Variables**: Store sensitive configuration in environment variables

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection**: Ensure your database is running and accessible
2. **Import Errors**: Run `go mod tidy` to resolve dependencies
3. **Port Conflicts**: Change the port if 8080 is already in use
4. **Configuration**: Verify all required configuration fields are set

### Getting Help

- Check the [main documentation](../README.md)
- Review the [API documentation](../docs/)
- Open an issue on GitHub

## 📝 Contributing

To add new examples:

1. Create a new directory under the appropriate category
2. Include a `main.go` file with a complete working example
3. Add a brief description in this README
4. Test the example thoroughly

## 📄 License

These examples are part of the GoAuth library and are licensed under the MIT License. 