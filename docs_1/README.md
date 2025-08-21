# GoAuth Documentation

This is the official documentation for GoAuth, a comprehensive Go authentication library with OAuth, JWT, and security features.

## What is GoAuth?

GoAuth is a production-ready authentication library for Go applications that provides:

- **Multiple Authentication Methods**: OAuth 2.0, JWT, Magic Links, Two-Factor Authentication
- **Framework Support**: Native support for popular Go web frameworks
- **Security Features**: Rate limiting, CSRF protection, reCAPTCHA integration
- **Flexible Storage**: Support for multiple database backends
- **Production Ready**: Built with security and scalability in mind

## Documentation Structure

### Getting Started

- [Introduction](docs/intro.md) - Welcome to GoAuth
- [Installation](docs/installation.md) - Install and setup GoAuth
- [Quick Start](docs/quickstart.md) - Get up and running quickly

### Core Features

- [Basic Authentication](docs/getting-started/basic-auth.md) - Email/password authentication
- [OAuth Setup](docs/getting-started/oauth-setup.md) - Social login integration
- [Custom Storage](docs/getting-started/custom-storage.md) - Custom storage backends

### Advanced Features

- [OAuth Features](docs/features/oauth.md) - Comprehensive OAuth support
- [JWT Features](docs/features/jwt.md) - JWT token management
- [Two-Factor Authentication](docs/features/two-factor.md) - 2FA implementation
- [Rate Limiting](docs/features/rate-limiting.md) - API rate limiting
- [Security Features](docs/features/security.md) - Advanced security measures
- [reCAPTCHA Integration](docs/features/recaptcha.md) - Bot protection

### Framework Integration

- [Gin Framework](docs/frameworks/gin.md) - Gin integration guide
- [Echo Framework](docs/frameworks/echo.md) - Echo integration guide
- [Fiber Framework](docs/frameworks/fiber.md) - Fiber integration guide
- [Chi Framework](docs/frameworks/chi.md) - Chi integration guide
- [Gorilla Mux](docs/frameworks/gorilla-mux.md) - Gorilla Mux integration guide
- [Iris Framework](docs/frameworks/iris.md) - Iris integration guide

### Configuration

- [Authentication Configuration](docs/configuration/auth.md) - Configure GoAuth

### API Reference

- [API Endpoints](docs/api/endpoints.md) - Complete API reference
- [Request/Response Models](docs/api/models.md) - Data models
- [Error Handling](docs/api/errors.md) - Error codes and handling

### Examples

- [Basic Authentication](docs/examples/basic-auth.md) - Complete authentication example
- [OAuth Setup](docs/examples/oauth-setup.md) - OAuth implementation example
- [Custom Storage](docs/examples/custom-storage.md) - Custom storage example

## Development

### Prerequisites

- Node.js 18.0 or above
- npm or yarn

### Installation

1. Install dependencies:

```bash
npm install
```

2. Start development server:

```bash
npm start
```

3. Build for production:

```bash
npm run build
```

4. Serve production build:

```bash
npm run serve
```

### Project Structure

```
docs/
├── intro.md                    # Introduction
├── installation.md             # Installation guide
├── quickstart.md              # Quick start tutorial
├── getting-started/           # Getting started guides
│   ├── basic-auth.md         # Basic authentication
│   ├── oauth-setup.md        # OAuth setup
│   └── custom-storage.md     # Custom storage
├── features/                  # Feature documentation
│   ├── oauth.md              # OAuth features
│   ├── jwt.md                # JWT features
│   ├── two-factor.md         # 2FA features
│   ├── rate-limiting.md      # Rate limiting
│   ├── security.md           # Security features
│   └── recaptcha.md          # reCAPTCHA integration
├── frameworks/                # Framework integration
│   ├── gin.md                # Gin framework
│   ├── echo.md               # Echo framework
│   ├── fiber.md              # Fiber framework
│   ├── chi.md                # Chi framework
│   ├── gorilla-mux.md        # Gorilla Mux
│   └── iris.md               # Iris framework
├── configuration/             # Configuration guides
│   └── auth.md               # Authentication config
├── api/                      # API reference
│   └── endpoints.md          # API endpoints
└── examples/                 # Implementation examples
    ├── basic-auth.md         # Basic auth example
    ├── oauth-setup.md        # OAuth example
    └── custom-storage.md     # Custom storage example
```

## Contributing

We welcome contributions to the GoAuth documentation! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Documentation Guidelines

1. **Use clear, concise language**
2. **Include code examples**
3. **Follow the existing structure**
4. **Test all code examples**
5. **Update the sidebar when adding new pages**

### Adding New Documentation

1. Create the new markdown file in the appropriate directory
2. Add the file to the sidebar configuration in `sidebars.ts`
3. Update this README if needed
4. Test the documentation locally
5. Submit a pull request

## Building and Deployment

### Local Development

```bash
# Start development server
npm start

# Build for production
npm run build

# Serve production build
npm run serve
```

### Deployment

The documentation can be deployed to various platforms:

- **GitHub Pages**: Use `npm run deploy`
- **Netlify**: Connect your repository and build with `npm run build`
- **Vercel**: Connect your repository and build with `npm run build`
- **AWS S3**: Build and upload the `build` directory

### Environment Variables

Create a `.env.local` file for local development:

```bash
# Docusaurus configuration
GATSBY_ALGOLIA_APP_ID=your-algolia-app-id
GATSBY_ALGOLIA_SEARCH_KEY=your-algolia-search-key
GATSBY_ALGOLIA_ADMIN_KEY=your-algolia-admin-key
```

## Support

- **Documentation Issues**: [GitHub Issues](https://github.com/your-org/goauth/issues)
- **Questions**: [GitHub Discussions](https://github.com/your-org/goauth/discussions)
- **Security Issues**: [Security Policy](SECURITY.md)

## License

This documentation is licensed under the same license as GoAuth. See the [LICENSE](../LICENSE) file for details.

## Acknowledgments

- Built with [Docusaurus](https://docusaurus.io/)
- Icons from [Feather Icons](https://feathericons.com/)
- Code highlighting with [Prism](https://prismjs.com/)
