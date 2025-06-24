import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CodeBlock, CodeBlockWithLines } from "@/components/ui/code-block";
import { ArrowLeft, Code, Zap, Shield } from "lucide-react";
import Link from "next/link";

export default function FrameworksPage() {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <div className="w-64 border-r bg-muted/40">
        <div className="p-6">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-xl font-bold">go-auth</h1>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Authentication library for Go
          </p>
        </div>
        
        <div className="p-4">
          <Link href="/" className="flex items-center text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Home
          </Link>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="container mx-auto p-8 max-w-6xl">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-4">Supported Frameworks</h1>
            <p className="text-lg text-muted-foreground">
              go-auth supports multiple popular Go web frameworks with native integration.
            </p>
          </div>

          {/* Framework Overview */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Gin</CardTitle>
                  <Badge variant="secondary">Popular</Badge>
                </div>
                <CardDescription>
                  Fast HTTP web framework with excellent performance
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">High Performance</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">Easy Integration</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Middleware Support</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/gin">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Echo</CardTitle>
                  <Badge variant="secondary">Modern</Badge>
                </div>
                <CardDescription>
                  High performance, extensible, minimalist Go web framework
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">High Performance</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">Minimalist API</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Extensible</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/echo">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Chi</CardTitle>
                  <Badge variant="secondary">Lightweight</Badge>
                </div>
                <CardDescription>
                  Lightweight, expressive, and scalable HTTP router
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Lightweight</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">Expressive</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Scalable</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/chi">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Fiber</CardTitle>
                  <Badge variant="secondary">Fast</Badge>
                </div>
                <CardDescription>
                  Express inspired web framework built on top of Fasthttp
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Express-like</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">Zero Memory Allocation</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Fast HTTP</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/fiber">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Gorilla Mux</CardTitle>
                  <Badge variant="secondary">Mature</Badge>
                </div>
                <CardDescription>
                  Powerful HTTP router and URL matcher for building Go web servers
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Mature</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">URL Matcher</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Middleware</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/gorilla-mux">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Iris</CardTitle>
                  <Badge variant="secondary">Feature-rich</Badge>
                </div>
                <CardDescription>
                  Fast, simple yet efficient HTTP web framework
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <Zap className="h-4 w-4 text-green-500" />
                    <span className="text-sm">Fast</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Code className="h-4 w-4 text-blue-500" />
                    <span className="text-sm">Feature-rich</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Shield className="h-4 w-4 text-purple-500" />
                    <span className="text-sm">Simple API</span>
                  </div>
                </div>
                <Button asChild className="w-full mt-4">
                  <Link href="/frameworks/iris">View Implementation</Link>
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Implementation Examples */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle>Implementation Examples</CardTitle>
              <CardDescription>
                See how to integrate go-auth with each framework
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="gin" className="w-full">
                <TabsList className="grid w-full grid-cols-6">
                  <TabsTrigger value="gin">Gin</TabsTrigger>
                  <TabsTrigger value="echo">Echo</TabsTrigger>
                  <TabsTrigger value="chi">Chi</TabsTrigger>
                  <TabsTrigger value="fiber">Fiber</TabsTrigger>
                  <TabsTrigger value="gorilla">Gorilla</TabsTrigger>
                  <TabsTrigger value="iris">Iris</TabsTrigger>
                </TabsList>

                <TabsContent value="gin" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/gin-gonic/gin
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "github.com/gin-gonic/gin"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    router := gin.Default()
    
    // Register auth routes
    authService.RegisterGinRoutes(router)
    
    // Protected routes
    protected := router.Group("/api")
    protected.Use(authService.GinAuthMiddleware())
    {
        protected.GET("/profile", func(c *gin.Context) {
            user := c.MustGet("user").(models.User)
            c.JSON(200, gin.H{"user": user})
        })
    }

    router.Run(":8080")
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="echo" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/labstack/echo/v4
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "github.com/labstack/echo/v4"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    e := echo.New()
    
    // Register auth routes
    authService.RegisterEchoRoutes(e)
    
    // Protected routes
    api := e.Group("/api")
    api.Use(authService.EchoAuthMiddleware())
    {
        api.GET("/profile", func(c echo.Context) error {
            user := c.Get("user").(models.User)
            return c.JSON(200, map[string]interface{}{"user": user})
        })
    }

    e.Start(":8080")
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="chi" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/go-chi/chi/v5
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    
    // Register auth routes
    authService.RegisterChiRoutes(r)
    
    // Protected routes
    r.Route("/api", func(r chi.Router) {
        r.Use(authService.ChiAuthMiddleware())
        r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
            user := r.Context().Value("user").(models.User)
            w.Header().Set("Content-Type", "application/json")
            w.Write([]byte(\`{"user": "profile data"}\`))
        })
    })

    http.ListenAndServe(":8080", r)
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="fiber" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/gofiber/fiber/v2
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    app := fiber.New()
    
    // Register auth routes
    authService.RegisterFiberRoutes(app)
    
    // Protected routes
    api := app.Group("/api")
    api.Use(authService.FiberAuthMiddleware())
    {
        api.Get("/profile", func(c *fiber.Ctx) error {
            user := c.Locals("user").(models.User)
            return c.JSON(fiber.Map{"user": user})
        })
    }

    app.Listen(":8080")
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="gorilla" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/gorilla/mux
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "net/http"
    "github.com/gorilla/mux"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    r := mux.NewRouter()
    
    // Register auth routes
    authService.RegisterGorillaMuxRoutes(r)
    
    // Protected routes
    api := r.PathPrefix("/api").Subrouter()
    api.Use(authService.GorillaMuxAuthMiddleware())
    api.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user").(models.User)
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(\`{"user": "profile data"}\`))
    }).Methods("GET")

    http.ListenAndServe(":8080", r)
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="iris" className="mt-6">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">Installation</h4>
                      <CodeBlock language="bash" title="Install Dependencies">
{`go get github.com/kataras/iris/v12
go get github.com/bete7512/goauth`}
                      </CodeBlock>
                    </div>
                    <div>
                      <h4 className="font-semibold mb-2">Basic Implementation</h4>
                      <CodeBlockWithLines language="go" title="main.go">
{`package main

import (
    "github.com/kataras/iris/v12"
    "github.com/bete7512/goauth"
    "github.com/bete7512/goauth/types"
)

func main() {
    config := types.Config{
        JWTSecret: "your-secret-key",
        Database: types.DatabaseConfig{
            Type: "postgres",
            URL:  "postgres://user:password@localhost:5432/dbname",
        },
    }

    authService, err := goauth.NewBuilder().
        WithConfig(config).
        Build()

    if err != nil {
        panic(err)
    }

    app := iris.New()
    
    // Register auth routes
    authRoutes := authService.GetRoutes()
    for _, route := range authRoutes {
        handler := authService.GetWrappedHandler(route)
        app.Handle(route.Method, route.Path, iris.FromStd(handler))
    }
    
    // Protected routes
    api := app.Party("/api")
    api.Use(func(ctx iris.Context) {
        // Custom auth middleware for Iris
        token := ctx.GetHeader("Authorization")
        if token == "" {
            ctx.StatusCode(401)
            ctx.JSON(iris.Map{"error": "unauthorized"})
            return
        }
        // Add user to context
        ctx.Values().Set("user", "user-data")
        ctx.Next()
    })
    {
        api.Get("/profile", func(ctx iris.Context) {
            user := ctx.Values().Get("user")
            ctx.JSON(iris.Map{"user": user})
        })
    }

    app.Listen(":8080")
}`}
                      </CodeBlockWithLines>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Comparison Table */}
          <Card>
            <CardHeader>
              <CardTitle>Framework Comparison</CardTitle>
              <CardDescription>
                Compare features and performance across supported frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-2">Framework</th>
                      <th className="text-left p-2">Performance</th>
                      <th className="text-left p-2">Learning Curve</th>
                      <th className="text-left p-2">Middleware</th>
                      <th className="text-left p-2">Community</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b">
                      <td className="p-2 font-medium">Gin</td>
                      <td className="p-2">
                        <Badge variant="secondary">Excellent</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Easy</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Rich</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Large</Badge>
                      </td>
                    </tr>
                    <tr className="border-b">
                      <td className="p-2 font-medium">Echo</td>
                      <td className="p-2">
                        <Badge variant="secondary">Excellent</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Easy</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Rich</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Large</Badge>
                      </td>
                    </tr>
                    <tr className="border-b">
                      <td className="p-2 font-medium">Chi</td>
                      <td className="p-2">
                        <Badge variant="secondary">Good</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Easy</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Standard</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Medium</Badge>
                      </td>
                    </tr>
                    <tr className="border-b">
                      <td className="p-2 font-medium">Fiber</td>
                      <td className="p-2">
                        <Badge variant="secondary">Excellent</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Easy</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Rich</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Growing</Badge>
                      </td>
                    </tr>
                    <tr className="border-b">
                      <td className="p-2 font-medium">Gorilla Mux</td>
                      <td className="p-2">
                        <Badge variant="secondary">Good</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Medium</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Standard</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Large</Badge>
                      </td>
                    </tr>
                    <tr>
                      <td className="p-2 font-medium">Iris</td>
                      <td className="p-2">
                        <Badge variant="secondary">Excellent</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Medium</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Rich</Badge>
                      </td>
                      <td className="p-2">
                        <Badge variant="outline">Medium</Badge>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}