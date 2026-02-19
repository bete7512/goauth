---
id: community
title: Community
sidebar_label: Community
description: Contribute to GoAuth and get help
---

# Community

## Get Help

- [GitHub Issues](https://github.com/bete7512/goauth/issues) — Report bugs and request features
- [GitHub Discussions](https://github.com/bete7512/goauth/discussions) — Ask questions and share ideas

## Contributing

Contributions are welcome. Here's how:

1. Fork the repository
2. Create a branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `make build` and `make test` to verify
5. Commit and push
6. Open a pull request

### Code Patterns

Follow the existing patterns:

- Exported interface / unexported struct for services
- `types.GoAuthError` for error returns
- Dot-notation route names (e.g., `core.signup`)
- Embedded swagger specs per module
- `config.Module` interface (8 methods) for all modules

### Adding a Module

Use the scaffolding scripts:

```bash
cd internal/modules
./new_module_with_route.sh mymodule      # Module with routes
./new_module_with_no_route.sh mymodule   # Middleware-only module
```

### Documentation

Help improve documentation by:

- Fixing errors or unclear explanations
- Adding examples
- Keeping code samples up to date

## Resources

- [GitHub Repository](https://github.com/bete7512/goauth)
- [Documentation](/docs/)
- [Quick Start](/docs/quickstart)
