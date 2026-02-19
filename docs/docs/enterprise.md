---
id: enterprise
title: Enterprise Deployment
sidebar_label: Enterprise
---

# Enterprise Deployment

GoAuth is designed to scale from single-instance startups to high-availability enterprise environments.

## Scalability

- **Stateless Authentication**: Default JWT-based [Stateless Module](modules/stateless.md) allows your API nodes to scale horizontally without shared state.
- **Database Pooling**: Leverages GORM's built-in connection pooling for efficient shared database access.
- **Async Processing**: Use external backends (Redis, RabbitMQ) via `AsyncBackend` for sending emails and processing events without blocking request threads.

## Security & Governance

- **Admin Module**: Dedicated [Admin Module](modules/admin.md) for managing large user bases with role-based access controls.
- **OAuth / SSO**: Integrate with enterprise identity providers (Google Workspace, Microsoft Azure AD) using the [OAuth Module](modules/oauth.md).
- **CSRF & Captcha**: Protect your public signup and login endpoints from automated attacks.

## Customizability

- **Framework Agnostic**: Deploy with `net/http`, Gin, Fiber, or Chi using standard adapters.
- **Storage Abstraction**: Implement `types.Storage` to use existing enterprise data stores or non-SQL backends.
- **Event-Driven**: Hook into any lifecycle event to trigger external workflows (e.g., syncing users to CRM).
