# GoAuth Demo - Next.js Interactive Application

A modern Next.js demo application showcasing **GoAuth's modular architecture** with a focus on the **Core Module** features. Built with shadcn/ui and Tailwind CSS for a beautiful, production-ready UI.

## 🎯 What This Demo Shows

This demo application demonstrates GoAuth's **Core Module** - the foundation of the authentication system. The core module is automatically registered and provides all essential authentication features.

### Core Module Features Demonstrated

✅ **User Registration (Signup)**
- Email/password registration
- Optional username support
- Optional phone number support
- Extended user attributes
- Real-time availability checking

✅ **User Authentication (Login)**
- Email/password login
- JWT token generation
- Refresh token support
- Session management

✅ **Profile Management**
- View user profile
- Update profile information
- Change password
- Extended attributes support

✅ **Password Reset Flow**
- Request password reset
- Email-based reset tokens
- Secure password reset

✅ **Email Verification**
- Send verification emails
- Verify email addresses
- Frontend callback handling

✅ **Phone Verification**
- Send verification codes
- Verify phone numbers

✅ **Availability Checking**
- Real-time email availability
- Username availability
- Phone number availability

## 🧩 Understanding the Modular Architecture

GoAuth uses a **modular, plug-and-play architecture**:

1. **Core Module** (Auto-registered): Essential authentication features - demonstrated in this demo
2. **Optional Modules** (Add as needed):
   - **Notification**: Email/SMS with SendGrid, Twilio, SMTP, Resend
   - **Two-Factor**: TOTP-based 2FA with backup codes
   - **OAuth**: Social login (Google, GitHub, Facebook, etc.)
   - **Rate Limiter**: IP-based rate limiting
   - **Captcha**: reCAPTCHA v3 and Cloudflare Turnstile
   - **CSRF**: Token-based CSRF protection
   - **Admin**: Admin-only user management endpoints
   - **Magic Link**: Passwordless authentication

### How to Add More Modules

To extend this demo with additional modules, update your backend:

```go
// Your Go backend
a, _ := auth.New(&config.Config{...})

// Add notification module
a.Use(notification.New(&notification.Config{
    EmailSender: senders.NewSendGridEmailSender(...),
    EnableWelcomeEmail: true,
}))

// Add two-factor authentication
a.Use(twofactor.New(&twofactor.TwoFactorConfig{
    Issuer: "MyApp",
}))

// Add rate limiting
a.Use(ratelimiter.New(&ratelimiter.RateLimiterConfig{
    RequestsPerMinute: 60,
}))

a.Initialize(context.Background())
```

Then extend the demo frontend with corresponding UI components!

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ or Bun
- Running GoAuth backend (see main README)

### 1. Install Dependencies

```bash
cd demo
npm install
# or
pnpm install
# or
bun install
```

### 2. Configure API Endpoint

The demo includes an interactive API configuration panel, but you can also set defaults in `src/config/demo-config.ts`:

```typescript
export const DEMO_CONFIG = {
  api: {
    baseUrl: 'http://localhost:8080',  // Your GoAuth server
    basePath: '/api/v1',               // Your API base path
    timeout: 10000,
  },
  features: {
    enableEmailVerification: true,
    enablePhoneVerification: true,
    enableUsername: true,
    enablePhoneNumber: true,
    enableExtendedAttributes: true,
  },
}
```

### 3. Start Development Server

```bash
npm run dev
# or
pnpm dev
# or
bun dev
```

### 4. Open Browser

Navigate to [http://localhost:3000](http://localhost:3000)

## 📂 Project Structure

```
demo/
├── src/
│   ├── app/                      # Next.js 14 app directory
│   │   ├── page.tsx             # Main demo page
│   │   ├── layout.tsx           # Root layout with metadata
│   │   └── globals.css          # Global styles + Tailwind
│   │
│   ├── components/
│   │   ├── ui/                  # shadcn/ui components
│   │   │   ├── button.tsx       # Button component
│   │   │   ├── input.tsx        # Input component
│   │   │   ├── card.tsx         # Card component
│   │   │   └── label.tsx        # Label component
│   │   │
│   │   ├── core/                # Core module UI components
│   │   │   ├── signup-form.tsx           # User registration form
│   │   │   ├── login-form.tsx            # Login form
│   │   │   ├── forgot-password-form.tsx  # Password reset form
│   │   │   └── availability-checker.tsx  # Availability checking UI
│   │   │
│   │   └── api-config-panel.tsx # Interactive API configuration
│   │
│   ├── lib/
│   │   ├── api-config.ts        # API client configuration & setup
│   │   └── utils.ts             # Utility functions (cn, etc.)
│   │
│   ├── services/
│   │   └── core-api.ts          # Core module API service layer
│   │
│   ├── types/
│   │   └── core.ts              # TypeScript types for Core module
│   │
│   └── config/
│       └── demo-config.ts       # Demo application configuration
│
├── package.json                 # Dependencies
├── tailwind.config.ts           # Tailwind CSS configuration
├── tsconfig.json                # TypeScript configuration
└── README.md                    # This file
```

## 🎨 Design System

### UI Components (shadcn/ui)

The demo uses [shadcn/ui](https://ui.shadcn.com/) - a collection of beautifully designed, accessible, and customizable React components:

- **Button**: Multiple variants (default, destructive, outline, ghost)
- **Input**: Form inputs with proper accessibility
- **Card**: Container components for content organization
- **Label**: Form labels with proper ARIA attributes

### Styling

- **Tailwind CSS**: Utility-first CSS framework
- **CSS Variables**: Theme customization via CSS variables
- **Dark Mode Support**: Built-in dark mode theming
- **Responsive Design**: Mobile-first responsive design

## 🔧 Configuration

### API Configuration

The demo includes a visual API configuration panel in the top-right corner. You can also configure defaults:

**File:** `src/config/demo-config.ts`

```typescript
export const DEMO_CONFIG = {
  api: {
    baseUrl: 'http://localhost:8080',    // GoAuth server URL
    basePath: '/api/v1',                 // API base path
    timeout: 10000,                      // Request timeout (ms)
  },
  features: {
    enableEmailVerification: true,       // Show email verification
    enablePhoneVerification: true,       // Show phone verification
    enableUsername: true,                // Show username field
    enablePhoneNumber: true,             // Show phone field
    enableExtendedAttributes: true,      // Show extended attributes
  },
  ui: {
    showApiEndpoints: true,              // Show endpoint reference
    animateTransitions: true,            // Enable animations
  },
}
```

### Backend Configuration

Make sure your GoAuth backend is configured for the core module:

```go
a, _ := auth.New(&config.Config{
    BasePath: "/api/v1",
    Core: &config.CoreConfig{
        RequireEmailVerification: true,
        RequirePhoneVerification: false,
        RequireUserName:          false,
        RequirePhoneNumber:       false,
    },
    FrontendConfig: &config.FrontendConfig{
        URL:                     "http://localhost:3000",
        VerifyEmailCallbackPath: "/verify-email",
        ResetPasswordPath:       "/reset-password",
    },
    CORS: &config.CORSConfig{
        Enabled:        true,
        AllowedOrigins: []string{"http://localhost:3000"},
    },
})
```

## 🔌 Core Module API Endpoints

The demo connects to these GoAuth endpoints:

### Authentication
- `POST /api/v1/signup` - User registration
- `POST /api/v1/login` - User authentication
- `POST /api/v1/logout` - User logout

### Profile Management
- `GET /api/v1/me` - Get current user
- `GET /api/v1/profile` - Get user profile
- `PUT /api/v1/profile` - Update user profile
- `PUT /api/v1/change-password` - Change password

### Password Reset
- `POST /api/v1/forgot-password` - Request password reset
- `POST /api/v1/reset-password` - Reset password with token

### Email Verification
- `POST /api/v1/send-verification-email` - Send verification email
- `GET /api/v1/verify-email?token=xxx` - Verify email (redirects to frontend)

### Phone Verification
- `POST /api/v1/send-verification-phone` - Send phone verification code
- `POST /api/v1/verify-phone` - Verify phone with code

### Availability Checking
- `POST /api/v1/availability/email` - Check email availability
- `POST /api/v1/availability/username` - Check username availability
- `POST /api/v1/availability/phone` - Check phone availability

## 🧩 Extending the Demo with More Modules

### Example: Adding Two-Factor Authentication UI

1. **Add types** (`src/types/twofactor.ts`):
```typescript
export interface TwoFactorSetupResponse {
  secret: string
  qr_url: string
  backup_codes: string[]
}
```

2. **Create API service** (`src/services/twofactor-api.ts`):
```typescript
export class TwoFactorApiService {
  async setup(): Promise<TwoFactorSetupResponse> {
    return apiClient.post('/2fa/setup')
  }
  
  async verify(code: string) {
    return apiClient.post('/2fa/verify', { code })
  }
}
```

3. **Create UI component** (`src/components/twofactor/setup-form.tsx`):
```typescript
export function TwoFactorSetup() {
  // Component implementation
}
```

4. **Add to main page** (`src/app/page.tsx`):
```typescript
import { TwoFactorSetup } from '@/components/twofactor/setup-form'
// Add to tab navigation
```

### Example: Adding OAuth Buttons

1. **Create OAuth component** (`src/components/oauth/oauth-buttons.tsx`):
```typescript
export function OAuthButtons() {
  return (
    <div className="grid gap-2">
      <Button onClick={() => window.location.href = '/api/v1/oauth/google'}>
        Sign in with Google
      </Button>
      <Button onClick={() => window.location.href = '/api/v1/oauth/github'}>
        Sign in with GitHub
      </Button>
    </div>
  )
}
```

2. **Add to login form**

## 📦 Dependencies

### Core Dependencies
- **Next.js 14**: React framework with App Router
- **React 18**: UI library
- **TypeScript**: Type safety

### UI & Styling
- **Tailwind CSS**: Utility-first CSS
- **shadcn/ui**: Component library
- **Lucide React**: Icon library
- **clsx**: Conditional className utility
- **tailwind-merge**: Merge Tailwind classes

### Development
- **ESLint**: Code linting
- **TypeScript**: Type checking

## 🚀 Available Scripts

```bash
# Development
npm run dev          # Start development server (http://localhost:3000)

# Production
npm run build        # Build for production
npm run start        # Start production server

# Code Quality
npm run lint         # Run ESLint
npm run type-check   # Run TypeScript type checking
```

## 🌐 Environment Variables

Create a `.env.local` file for environment-specific configuration:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080
NEXT_PUBLIC_API_BASE_PATH=/api/v1
```

## 📱 Responsive Design

The demo is fully responsive and works on:
- 📱 Mobile devices (320px+)
- 📱 Tablets (768px+)
- 💻 Desktop (1024px+)
- 🖥️ Large screens (1280px+)

## 🎨 Customization

### Theming

Modify `src/app/globals.css` to customize colors:

```css
:root {
  --background: 0 0% 100%;
  --foreground: 222.2 84% 4.9%;
  --primary: 262.1 83.3% 57.8%;
  /* ... more variables */
}
```

### Component Styling

All components use Tailwind CSS and can be customized by modifying their class names or extending Tailwind config.

## 🤝 Contributing

Want to improve the demo? Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This demo is part of the GoAuth project. See the main project [LICENSE](../LICENSE) for details.

## 🔗 Links

- [GoAuth Main Repository](../)
- [GoAuth Documentation](../docs/)
- [Module Documentation](../internal/modules/README.md)
- [shadcn/ui Documentation](https://ui.shadcn.com/)
- [Next.js Documentation](https://nextjs.org/docs)

---

**Built with ❤️ to showcase GoAuth's powerful modular architecture**
