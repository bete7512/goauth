import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Settings, Database, Shield, Mail, Bell } from "lucide-react";
import Link from "next/link";

export default function ConfigurationPage() {
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
        <div className="container mx-auto p-8 max-w-4xl">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-4">Configuration</h1>
            <p className="text-lg text-muted-foreground">
              Learn about all configuration options available in go-auth.
            </p>
          </div>

          {/* Basic Configuration */}
          <Card className="mb-8">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Settings className="h-5 w-5 mr-2" />
                Basic Configuration
              </CardTitle>
              <CardDescription>
                Essential configuration options for getting started
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                <pre><code className="text-foreground">
{`config := types.Config{
    // Required: JWT secret for token signing
    JWTSecret: "your-super-secret-jwt-key",

    // Required: Database configuration
    Database: types.DatabaseConfig{
        Type: "postgres", // postgres, mysql, mongodb
        URL:  "postgres://user:password@localhost:5432/dbname",
    },

    // Required: Authentication configuration
    AuthConfig: types.AuthConfig{
        Cookie: types.CookieConfig{
            Name:           "auth_token",
            AccessTokenTTL: 3600,   // 1 hour
            RefreshTokenTTL: 604800, // 7 days
            Path:           "/",
            MaxAge:         604800,
            Secure:         false,   // Set to true in production
            HttpOnly:       true,
            SameSite:       "lax",
        },
    },
}`}
                </code></pre>
              </div>
            </CardContent>
          </Card>

          {/* Configuration Sections */}
          <Tabs defaultValue="database" className="w-full">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="database">Database</TabsTrigger>
              <TabsTrigger value="auth">Auth</TabsTrigger>
              <TabsTrigger value="oauth">OAuth</TabsTrigger>
              <TabsTrigger value="security">Security</TabsTrigger>
              <TabsTrigger value="advanced">Advanced</TabsTrigger>
            </TabsList>

            {/* Database Configuration */}
            <TabsContent value="database" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Database className="h-5 w-5 mr-2" />
                    Database Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure your database connection and storage options
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold mb-2">Supported Databases</h4>
                      <div className="flex flex-wrap gap-2 mb-4">
                        <Badge variant="secondary">PostgreSQL</Badge>
                        <Badge variant="secondary">MySQL</Badge>
                        <Badge variant="secondary">MongoDB</Badge>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Configuration Example</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`Database: types.DatabaseConfig{
    Type: "postgres", // postgres, mysql, mongodb
    URL:  "postgres://user:password@localhost:5432/dbname",

    // Optional: Connection pool settings
    MaxOpenConns: 25,
    MaxIdleConns: 5,
    ConnMaxLifetime: 300, // 5 minutes

    // Optional: SSL settings (PostgreSQL)
    SSLMode: "require",

    // Optional: Custom storage repository
    EnableCustomStorageRepository: false,
}`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Connection Strings</h4>
                      <div className="space-y-2">
                        <div>
                          <span className="font-medium">PostgreSQL:</span>
                          <div className="bg-muted p-2 rounded font-mono text-sm mt-1">
                            postgres://user:password@localhost:5432/dbname
                          </div>
                        </div>
                        <div>
                          <span className="font-medium">MySQL:</span>
                          <div className="bg-muted p-2 rounded font-mono text-sm mt-1">
                            user:password@tcp(localhost:3306)/dbname?parseTime=true
                          </div>
                        </div>
                        <div>
                          <span className="font-medium">MongoDB:</span>
                          <div className="bg-muted p-2 rounded font-mono text-sm mt-1">
                            mongodb://user:password@localhost:27017/dbname?authSource=admin
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Auth Configuration */}
            <TabsContent value="auth" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Shield className="h-5 w-5 mr-2" />
                    Authentication Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure authentication behavior and cookie settings
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold mb-2">Cookie Configuration</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`AuthConfig: types.AuthConfig{
    Cookie: types.CookieConfig{
        Name:           "auth_token",     // Cookie name
        AccessTokenTTL: 3600,            // Access token lifetime (seconds)
        RefreshTokenTTL: 604800,         // Refresh token lifetime (seconds)
        Path:           "/",             // Cookie path
        MaxAge:         604800,          // Cookie max age (seconds)
        Secure:         false,           // HTTPS only (set true in production)
        HttpOnly:       true,            // Prevent XSS attacks
        SameSite:       "lax",           // CSRF protection
        Domain:         "",              // Cookie domain (optional)
    },

    // Optional: Enable email verification
    EnableEmailVerification: true,
    EmailVerificationURL: "https://yourapp.com/verify",

    // Optional: Enable SMS verification
    EnableSmsVerification: false,

    // Optional: Enable two-factor authentication
    EnableTwoFactor: false,
    TwoFactorMethod: "totp", // totp, sms

    // Optional: Password policy
    PasswordPolicy: types.PasswordPolicy{
        MinLength:      8,
        RequireUppercase: true,
        RequireLowercase: true,
        RequireNumbers:   true,
        RequireSymbols:   false,
        HashSaltLength:   32,
    },
}`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Features</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">Email Verification</Badge>
                          <span className="text-sm text-muted-foreground">Verify user email addresses</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">SMS Verification</Badge>
                          <span className="text-sm text-muted-foreground">Verify user phone numbers</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">Two-Factor Auth</Badge>
                          <span className="text-sm text-muted-foreground">TOTP or SMS-based 2FA</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline">Password Policy</Badge>
                          <span className="text-sm text-muted-foreground">Enforce strong passwords</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* OAuth Configuration */}
            <TabsContent value="oauth" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Mail className="h-5 w-5 mr-2" />
                    OAuth Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure OAuth providers for social login
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold mb-2">Supported Providers</h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                        <Badge variant="secondary">Google</Badge>
                        <Badge variant="secondary">GitHub</Badge>
                        <Badge variant="secondary">Facebook</Badge>
                        <Badge variant="secondary">Microsoft</Badge>
                        <Badge variant="secondary">Apple</Badge>
                        <Badge variant="secondary">Discord</Badge>
                        <Badge variant="secondary">Twitter</Badge>
                        <Badge variant="secondary">LinkedIn</Badge>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Configuration Example</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`Providers: types.ProvidersConfig{
    Enabled: []string{"google", "github", "facebook"},

    Google: types.ProviderConfig{
        ClientID:     "your-google-client-id",
        ClientSecret: "your-google-client-secret",
        RedirectURL:  "https://yourapp.com/auth/google/callback",
    },

    GitHub: types.ProviderConfig{
        ClientID:     "your-github-client-id",
        ClientSecret: "your-github-client-secret",
        RedirectURL:  "https://yourapp.com/auth/github/callback",
    },

    Facebook: types.ProviderConfig{
        ClientID:     "your-facebook-client-id",
        ClientSecret: "your-facebook-client-secret",
        RedirectURL:  "https://yourapp.com/auth/facebook/callback",
    },
}`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Provider Setup</h4>
                      <div className="space-y-2">
                        <div className="p-3 border rounded">
                          <h5 className="font-medium">Google</h5>
                          <p className="text-sm text-muted-foreground">
                            Create OAuth 2.0 credentials in Google Cloud Console
                          </p>
                        </div>
                        <div className="p-3 border rounded">
                          <h5 className="font-medium">GitHub</h5>
                          <p className="text-sm text-muted-foreground">
                            Register OAuth app in GitHub Developer Settings
                          </p>
                        </div>
                        <div className="p-3 border rounded">
                          <h5 className="font-medium">Facebook</h5>
                          <p className="text-sm text-muted-foreground">
                            Create Facebook App in Facebook Developers
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Security Configuration */}
            <TabsContent value="security" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Shield className="h-5 w-5 mr-2" />
                    Security Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure security features and rate limiting
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold mb-2">Rate Limiting</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// Enable rate limiting
EnableRateLimiter: true,
RateLimiter: types.RateLimiterConfig{
    Type: "redis", // memory, redis
    Redis: types.RedisConfig{
        URL: "redis://localhost:6379",
    },
    Limits: map[string]types.Limit{
        "login": {
            Requests: 5,
            Window:   300, // 5 minutes
        },
        "register": {
            Requests: 3,
            Window:   3600, // 1 hour
        },
    },
},`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">reCAPTCHA</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// Enable reCAPTCHA
EnableRecaptcha: true,
RecaptchaConfig: &types.RecaptchaConfig{
    SiteKey:   "your-recaptcha-site-key",
    SecretKey: "your-recaptcha-secret-key",
    Provider:  "google", // google, cloudflare
},`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">JWT Configuration</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// JWT settings
JWTSecret: "your-super-secret-jwt-key",
EnableAddCustomJWTClaims: false,
CustomJWTClaimsProvider: nil, // Custom function to add claims

// Optional: Custom JWT claims
CustomJWTClaimsProvider: func(user types.User) map[string]interface{} {
    return map[string]interface{}{
        "role": user.Role,
        "permissions": user.Permissions,
    }
},`}
                        </code></pre>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Advanced Configuration */}
            <TabsContent value="advanced" className="mt-6">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Settings className="h-5 w-5 mr-2" />
                    Advanced Configuration
                  </CardTitle>
                  <CardDescription>
                    Advanced features and customization options
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div>
                      <h4 className="font-semibold mb-2">Hooks</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// Custom hooks for events
Hooks: types.HooksConfig{
    OnUserRegistered: func(user types.User) {
        // Send welcome email
    },
    OnUserLoggedIn: func(user types.User) {
        // Log login activity
    },
    OnPasswordChanged: func(user types.User) {
        // Send password change notification
    },
},`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Email Configuration</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// Email sender configuration
EmailSender: types.EmailSender{
    Host:     "smtp.gmail.com",
    Port:     587,
    Username: "your-email@gmail.com",
    Password: "your-app-password",
    From:     "noreply@yourapp.com",
},`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">SMS Configuration</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// SMS sender configuration
SMSSender: types.SMSSender{
    Provider: "twilio", // twilio, aws-sns, etc.
    AccountSID: "your-twilio-account-sid",
    AuthToken:  "your-twilio-auth-token",
    FromNumber: "+1234567890",
},`}
                        </code></pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Swagger Documentation</h4>
                      <div className="bg-muted p-4 rounded-lg font-mono text-sm">
                        <pre><code className="text-foreground">
{`// Enable Swagger documentation
Swagger: types.SwaggerConfig{
    Enable:      true,
    Title:       "go-auth API",
    Version:     "1.0.0",
    Description: "Authentication API documentation",
    DocPath:     "/docs",
    Host:        "localhost:8080",
},`}
                        </code></pre>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          {/* Complete Example */}
          <Card className="mt-8">
            <CardHeader>
              <CardTitle>Complete Configuration Example</CardTitle>
              <CardDescription>
                A complete configuration example with all features enabled
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="bg-muted p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <pre><code className="text-foreground">
{`config := types.Config{
    // Basic settings
    JWTSecret: "your-super-secret-jwt-key-change-this-in-production",

    // Database
    Database: types.DatabaseConfig{
        Type: "postgres",
        URL:  "postgres://user:password@localhost:5432/goauth_db",
    },

    // Authentication
    AuthConfig: types.AuthConfig{
        Cookie: types.CookieConfig{
            Name:           "auth_token",
            AccessTokenTTL: 3600,
            RefreshTokenTTL: 604800,
            Path:           "/",
            MaxAge:         604800,
            Secure:         false, // Set to true in production
            HttpOnly:       true,
            SameSite:       "lax",
        },
        EnableEmailVerification: true,
        EmailVerificationURL: "https://yourapp.com/verify",
        EnableTwoFactor: false,
        TwoFactorMethod: "totp",
        PasswordPolicy: types.PasswordPolicy{
            MinLength:      8,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireNumbers:   true,
            RequireSymbols:   false,
            HashSaltLength:   32,
        },
    },

    // OAuth providers
    Providers: types.ProvidersConfig{
        Enabled: []string{"google", "github"},
        Google: types.ProviderConfig{
            ClientID:     "your-google-client-id",
            ClientSecret: "your-google-client-secret",
            RedirectURL:  "https://yourapp.com/auth/google/callback",
        },
        GitHub: types.ProviderConfig{
            ClientID:     "your-github-client-id",
            ClientSecret: "your-github-client-secret",
            RedirectURL:  "https://yourapp.com/auth/github/callback",
        },
    },

    // Security
    EnableRateLimiter: true,
    RateLimiter: types.RateLimiterConfig{
        Type: "memory",
        Limits: map[string]types.Limit{
            "login": {Requests: 5, Window: 300},
            "register": {Requests: 3, Window: 3600},
        },
    },

    EnableRecaptcha: true,
    RecaptchaConfig: &types.RecaptchaConfig{
        SiteKey:   "your-recaptcha-site-key",
        SecretKey: "your-recaptcha-secret-key",
        Provider:  "google",
    },

    // Email
    EmailSender: types.EmailSender{
        Host:     "smtp.gmail.com",
        Port:     587,
        Username: "your-email@gmail.com",
        Password: "your-app-password",
        From:     "noreply@yourapp.com",
    },

    // Swagger
    Swagger: types.SwaggerConfig{
        Enable:      true,
        Title:       "go-auth API",
        Version:     "1.0.0",
        Description: "Authentication API documentation",
        DocPath:     "/docs",
        Host:        "localhost:8080",
    },
}`}
                </code></pre>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}