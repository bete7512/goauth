---
id: community
title: Community
description: "Get help with GoAuth, the open-source Go authentication library: ask questions, report a bug or a security vulnerability, and contribute code or documentation."
keywords: ["goauth github", "contribute goauth", "goauth support"]
sidebar_label: Community
---

# Community

GoAuth is pre-1.0 and maintained by one developer. A report that something was confusing is as useful as a bug report.

## Get Help

- **A question, a bug or a feature request:** open a [GitHub issue](https://github.com/bete7512/goauth/issues). For a bug, include the GoAuth version, your database, the modules you registered and the smallest code that shows it.
- **A security problem:** report it privately, as described in [SECURITY.md](https://github.com/bete7512/goauth/blob/main/SECURITY.md). Do not open a public issue.

## Contributing

Contributions are welcome. For anything larger than a small fix, open an issue first.

1. Fork the repository and create a branch.
2. Make your changes and run `make check`, which runs everything CI runs except the database contract tests.
3. Open a pull request.

[CONTRIBUTING.md](https://github.com/bete7512/goauth/blob/main/CONTRIBUTING.md) has the tools, the checks and the conventions.

### Code Patterns

- Services are an exported interface with an unexported struct behind it.
- Services and handlers return `types.GoAuthError`. Lifecycle and storage contracts return an ordinary `error`.
- Route names use dot notation, such as `core.signup`.
- Each module embeds its OpenAPI spec.
- A module implements `config.Component` (`Name` and `Init`) plus the optional capabilities it needs. The eight-method `config.Module` interface still works.

### Adding a Module

The scaffolding scripts create the files:

```bash
cd internal/modules
./new_module_with_route.sh mymodule      # Module with routes
./new_module_with_no_route.sh mymodule   # Middleware-only module
```

A new module also needs its docs page, its OpenAPI spec and a CHANGELOG entry.

### Documentation

Fixing something wrong or unclear, adding an example, or updating a code sample that no longer compiles all help. The pages live in `docs/docs/`.

## Resources

- [GitHub repository](https://github.com/bete7512/goauth)
- [Changelog](https://github.com/bete7512/goauth/blob/main/CHANGELOG.md)
- [Quick Start](quickstart.md)
