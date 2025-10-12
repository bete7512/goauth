# Go-Auth Demo

A Next.js demo application showcasing the Go-Auth authentication system with shadcn/ui and Tailwind CSS.

## Features

- **Modular Architecture**: Easy to extend with new Go-Auth modules
- **Modern UI**: Built with shadcn/ui components and Tailwind CSS
- **TypeScript**: Full type safety with Go-Auth API types
- **Interactive Demo**: Test all core authentication features
- **Configurable**: Easy endpoint and feature configuration

## Core Module Features

- ✅ User Registration (Signup)
- ✅ User Authentication (Login)
- ✅ User Logout
- ✅ Profile Management
- ✅ Password Reset
- ✅ Email Verification
- ✅ Phone Verification
- ✅ Availability Checking (Email, Username, Phone)

## Quick Start

1. **Install Dependencies**
   ```bash
   cd demo
   npm install
   ```

2. **Configure API Endpoint**
   Edit `src/config/demo-config.ts`:
   ```typescript
   export const DEMO_CONFIG = {
     api: {
       baseUrl: 'http://localhost:8080',  // Your Go-Auth server
       basePath: '/api/v1',              // Your API base path
       timeout: 10000,
     },
     // ... other config
   }
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   ```

4. **Open Browser**
   Navigate to `http://localhost:3000`

## Project Structure

```
demo/
├── src/
│   ├── app/                    # Next.js app directory
│   │   ├── page.tsx           # Main demo page
│   │   ├── layout.tsx         # Root layout
│   │   └── globals.css        # Global styles
│   ├── components/
│   │   ├── ui/                # shadcn/ui components
│   │   │   ├── button.tsx
│   │   │   ├── input.tsx
│   │   │   ├── card.tsx
│   │   │   └── label.tsx
│   │   └── core/              # Core module components
│   │       ├── signup-form.tsx
│   │       ├── login-form.tsx
│   │       ├── forgot-password-form.tsx
│   │       └── availability-checker.tsx
│   ├── lib/
│   │   ├── api-config.ts      # API client configuration
│   │   └── utils.ts           # Utility functions
│   ├── services/
│   │   └── core-api.ts        # Core API service
│   ├── types/
│   │   └── core.ts            # TypeScript types
│   └── config/
│       └── demo-config.ts     # Demo configuration
├── package.json
├── tailwind.config.ts
├── tsconfig.json
└── README.md
```

## Configuration

### API Configuration

Update `src/config/demo-config.ts` to match your Go-Auth server:

```typescript
export const DEMO_CONFIG = {
  api: {
    baseUrl: 'http://localhost:8080',    // Your server URL
    basePath: '/api/v1',                // Your API base path
    timeout: 10000,
  },
  // ... rest of config
}
```

### Feature Flags

Enable/disable features in the demo:

```typescript
features: {
  enableEmailVerification: true,
  enablePhoneVerification: true,
  enableUsername: true,
  enablePhoneNumber: true,
  enableExtendedAttributes: true,
}
```

## Adding New Modules

To add support for new Go-Auth modules (OAuth, 2FA, etc.):

1. **Create Module Types**
   ```typescript
   // src/types/oauth.ts
   export interface OAuthRequest {
     provider: string
     code: string
   }
   ```

2. **Create API Service**
   ```typescript
   // src/services/oauth-api.ts
   export class OAuthApiService {
     async authenticate(data: OAuthRequest) {
       // Implementation
     }
   }
   ```

3. **Create UI Components**
   ```typescript
   // src/components/oauth/oauth-button.tsx
   export function OAuthButton({ provider }: { provider: string }) {
     // Implementation
   }
   ```

4. **Update Configuration**
   ```typescript
   // src/lib/api-config.ts
   export const defaultModules: GoAuthModules = {
     core: { /* ... */ },
     oauth: {
       name: 'oauth',
       enabled: true,
       endpoints: {
         authenticate: '/oauth/authenticate',
         callback: '/oauth/callback',
       }
     }
   }
   ```

## API Endpoints

The demo connects to these Go-Auth core module endpoints:

- `POST /signup` - User registration
- `POST /login` - User authentication
- `POST /logout` - User logout
- `GET /me` - Get current user
- `GET /profile` - Get user profile
- `PUT /profile` - Update user profile
- `PUT /change-password` - Change password
- `POST /forgot-password` - Request password reset
- `POST /reset-password` - Reset password
- `POST /send-verification-email` - Send email verification
- `POST /verify-email` - Verify email
- `POST /send-verification-phone` - Send phone verification
- `POST /verify-phone` - Verify phone
- `POST /availability/email` - Check email availability
- `POST /availability/username` - Check username availability
- `POST /availability/phone` - Check phone availability

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint

### Dependencies

- **Next.js 14** - React framework
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **shadcn/ui** - UI components
- **Lucide React** - Icons

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This demo is part of the Go-Auth project. See the main project for license information.

