---
id: gin
title: Gin Framework
sidebar_label: Gin
description: Mount GoAuth's routes on a Gin router with the Gin adapter.
---

# Gin Framework

GoAuth's routes are ordinary `net/http` handlers. The Gin adapter mounts them on a Gin router and translates path parameters, so `/sessions/{id}` becomes `/sessions/:id`.

## Install

The adapter is its own Go module:

```bash
go get github.com/bete7512/goauth/pkg/adapters/ginadapter@v0.3.0-beta.1
```

## Register the routes

Create and initialize `a` as in the [Quick Start](../quickstart.md), then:

```go
router := gin.Default()
ginadapter.Register(router, a)
if err := router.Run(":8080"); err != nil {
    return err
}
```

Import `github.com/gin-gonic/gin` and `github.com/bete7512/goauth/pkg/adapters/ginadapter`. This fragment belongs in a function that returns `error`.

## Stopping cleanly

For a clean shutdown, serve `router` through an `http.Server`, stop that server first, and then shut down GoAuth. The Quick Start shows the pattern under [Before real users sign in](../quickstart.md#before-real-users-sign-in).

## Developing against a checkout

With a local copy of this repository, add a `replace` line for the root module and another for the adapter module. See [Installation](../installation.md).

## Chi and Fiber

They work the same way: install `pkg/adapters/chiadapter` or `pkg/adapters/fiberadapter`, then call `chiadapter.Register(router, a)` or `fiberadapter.Register(app, a)`.
