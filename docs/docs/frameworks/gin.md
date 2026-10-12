---
id: gin
title: Gin Framework
sidebar_label: Gin
---

# Gin Framework

The Gin adapter is a separate Go module. Install it alongside the core library:

```bash
go get github.com/bete7512/goauth/pkg/adapters/ginadapter
```

After successfully creating and initializing `a`, register its routes:

```go
router := gin.Default()
ginadapter.Register(router, a)
if err := router.Run(":8080"); err != nil {
    return err
}
```

Import `github.com/gin-gonic/gin` and `github.com/bete7512/goauth/pkg/adapters/ginadapter`. This fragment belongs in a function returning `error`. For graceful shutdown, serve `router` through an `http.Server`, stop the server, then shut down GoAuth as shown in [Quick Start](../quickstart.md).

When developing against this repository, add local `replace` directives for both the root module and the adapter module. Published adapter versions may target an older API. See [Installation](../installation.md).
