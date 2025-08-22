---
id: showcase
title: GoAuth Showcase
sidebar_label: Showcase
description: Explore real-world examples and implementations of GoAuth
---

<div className="showcase-page">

# 🚀 GoAuth Showcase

Discover how developers are using GoAuth to build secure authentication systems. Explore real-world examples, sample projects, and implementation patterns.

## 🌟 Featured Examples

<div className="example-card">

### Basic Authentication

A simple yet secure username/password authentication system.

**Features:**

<ul className="feature-list">
<li>User registration and login</li>
<li>Password hashing with bcrypt</li>
<li>Session management</li>
<li>Rate limiting protection</li>
</ul>

<div className="tech-stack">
**Tech Stack:**

- Go + Gin framework
- PostgreSQL database
- Redis for sessions
- Docker deployment
</div>

<a href="https://github.com/your-org/goauth-examples/tree/main/basic-auth" className="github-link">View on GitHub</a>
<a href="https://basic-auth-demo.goauth.dev" className="demo-link">Live Demo</a>

</div>

---

<div className="example-card">

### OAuth Integration

Complete OAuth 2.0 implementation with multiple providers.

**Providers Supported:**

<ul className="feature-list">
<li>Google OAuth 2.0</li>
<li>GitHub OAuth</li>
<li>Facebook Login</li>
<li>Custom OAuth server</li>
</ul>

**Features:**

<ul className="feature-list">
<li>JWT token generation</li>
<li>Refresh token rotation</li>
<li>User profile management</li>
<li>Social login buttons</li>
</ul>

<a href="https://github.com/your-org/goauth-examples/tree/main/oauth-integration" className="github-link">View on GitHub</a>
<a href="https://oauth-demo.goauth.dev" className="demo-link">Live Demo</a>

</div>

---

<div className="example-card">

### JWT Implementation

Advanced JWT-based authentication with enhanced security.

**Security Features:**

<ul className="feature-list">
<li>Access & refresh token pairs</li>
<li>Token blacklisting</li>
<li>Automatic token rotation</li>
<li>Claims validation</li>
</ul>

**Use Cases:**

<ul className="feature-list">
<li>Microservices authentication</li>
<li>API gateway security</li>
<li>Mobile app authentication</li>
<li>Single sign-on (SSO)</li>
</ul>

<a href="https://github.com/your-org/goauth-examples/tree/main/jwt-implementation" className="github-link">View on GitHub</a>
<a href="https://jwt-demo.goauth.dev" className="demo-link">Live Demo</a>

</div>

---

<div className="example-card">

### Two-Factor Authentication

Enhanced security with TOTP-based 2FA implementation.

**2FA Methods:**

<ul className="feature-list">
<li>Time-based One-Time Password (TOTP)</li>
<li>SMS verification</li>
<li>Email verification</li>
<li>Hardware security keys</li>
</ul>

**Features:**

<ul className="feature-list">
<li>QR code generation for authenticator apps</li>
<li>Backup codes system</li>
<li>Remember device option</li>
<li>Admin override capabilities</li>
</ul>

<a href="https://github.com/your-org/goauth-examples/tree/main/two-factor-auth" className="github-link">View on GitHub</a>
<a href="https://2fa-demo.goauth.dev" className="demo-link">Live Demo</a>

</div>

<div className="example-card">

### Rate Limiting & Security

Production-ready security features for high-traffic applications.

**Security Measures:**

<ul className="feature-list">
<li>IP-based rate limiting</li>
<li>Account lockout protection</li>
<li>Brute force detection</li>
<li>CAPTCHA integration</li>
</ul>

**Performance:**

<ul className="feature-list">
<li>Redis-backed rate limiting</li>
<li>Distributed rate limiting</li>
<li>Custom rate limit rules</li>
<li>Monitoring and alerts</li>
</ul>

<a href="https://github.com/your-org/goauth-examples/tree/main/security-features" className="github-link">View on GitHub</a>
<a href="https://security-demo.goauth.dev" className="demo-link">Live Demo</a>

</div>

---

## 🏗️ Enterprise Solutions

<div className="enterprise-section">

### Multi-Tenant Authentication

Scalable authentication system for SaaS applications.

**Features:**

<ul className="feature-list">
<li>Tenant isolation</li>
<li>Custom branding per tenant</li>
<li>Role-based access control</li>
<li>Audit logging</li>
</ul>

<a href="https://github.com/your-org/goauth-enterprise/tree/main/multi-tenant" className="github-link">View on GitHub</a>

### SSO Integration

Enterprise single sign-on with SAML and OIDC support.

**Protocols:**

<ul className="feature-list">
<li>SAML 2.0</li>
<li>OpenID Connect</li>
<li>LDAP integration</li>
<li>Active Directory sync</li>
</ul>

<a href="https://github.com/your-org/goauth-enterprise/tree/main/sso-integration" className="github-link">View on GitHub</a>

</div>

---

## 🚀 Getting Started with Examples

<div className="getting-started">

### Quick Setup

```bash
# Clone the examples repository
git clone https://github.com/your-org/goauth-examples.git

# Navigate to a specific example
cd goauth-examples/basic-auth

# Install dependencies
go mod download

# Run the example
go run main.go
```

### Docker Deployment

```bash
# Build and run with Docker
docker build -t goauth-example .
docker run -p 8080:8080 goauth-example
```

</div>

---

## 📚 Learning Resources

- **[Documentation](/docs)** - Complete API reference
- **[Tutorials](/docs/getting-started)** - Step-by-step guides
- **[Blog](/blog)** - Latest updates and tips
- **[Community](/docs/community)** - Get help and contribute

---

## 🤝 Contribute Your Example

<div className="contribute-section">

Have a great GoAuth implementation? Share it with the community!

1. **Fork** our examples repository
2. **Create** a new example directory
3. **Add** comprehensive documentation
4. **Submit** a pull request

<a href="https://github.com/your-org/goauth-examples/pulls" className="github-link">Submit Your Example</a>

</div>

---

_Ready to build something amazing? Start with our [Getting Started Guide](/docs/getting-started/basic-auth) or explore the examples above!_

</div>
