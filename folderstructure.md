# go-auth

> Generated with [foldermd](https://github.com/yourusername/foldermd) on 2025-06-25 15:40:01

## 📊 Project Overview

- **Total Files:** 31927
- **Total Directories:** 3740
- **Project Root:** `.`

## 📁 Project Structure

```
Legend: 📁 Directory | 📄 File
```

```
├── dev/
│   ├── emails/
│   │   └── emails.go
│   ├── repositories/
│   │   ├── repository.go
│   │   ├── tokenRepository.go
│   │   └── userRepository.go
│   ├── exampleConfig.go
│   ├── go.mod
│   ├── go.sum
│   ├── main.go
│   └── makefile
├── docs/
│   ├── public/
│   │   ├── file.svg
│   │   ├── globe.svg
│   │   ├── next.svg
│   │   ├── vercel.svg
│   │   └── window.svg
│   ├── src/
│   │   ├── app/
│   │   │   ├── api/
│   │   │   │   ├── endpoints/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── hooks/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── models/
│   │   │   │       └── page.tsx
│   │   │   ├── configuration/
│   │   │   │   └── page.tsx
│   │   │   ├── examples/
│   │   │   │   ├── basic-auth/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── custom-storage/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── oauth-setup/
│   │   │   │       └── page.tsx
│   │   │   ├── features/
│   │   │   │   ├── jwt/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── oauth/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── rate-limiting/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── recaptcha/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── two-factor/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── frameworks/
│   │   │   │   ├── chi/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── echo/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── fiber/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── gin/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── gorilla-mux/
│   │   │   │   │   └── page.tsx
│   │   │   │   ├── iris/
│   │   │   │   │   └── page.tsx
│   │   │   │   └── page.tsx
│   │   │   ├── installation/
│   │   │   │   └── page.tsx
│   │   │   ├── quickstart/
│   │   │   │   └── page.tsx
│   │   │   ├── favicon.ico
│   │   │   ├── globals.css
│   │   │   ├── layout.tsx
│   │   │   └── page.tsx
│   │   ├── components/
│   │   │   └── ui/
│   │   │       ├── badge.tsx
│   │   │       ├── button.tsx
│   │   │       ├── card.tsx
│   │   │       ├── checkbox.tsx
│   │   │       ├── code-block.tsx
│   │   │       ├── input.tsx
│   │   │       ├── navigation-menu.tsx
│   │   │       ├── radio-group.tsx
│   │   │       ├── scroll-area.tsx
│   │   │       ├── select.tsx
│   │   │       ├── separator.tsx
│   │   │       ├── sheet.tsx
│   │   │       ├── switch.tsx
│   │   │       ├── tabs.tsx
│   │   │       └── textarea.tsx
│   │   └── lib/
│   │       └── utils.ts
│   ├── README.md
│   ├── components.json
│   ├── eslint.config.mjs
│   ├── next-env.d.ts
│   ├── next.config.ts
│   ├── package.json
│   ├── pnpm-lock.yaml
│   ├── postcss.config.mjs
│   ├── start-docs.sh
│   └── tsconfig.json
├── examples/
│   ├── basic/
│   │   └── main.go
│   ├── custom/
│   ├── frameworks/
│   │   ├── chi/
│   │   ├── echo/
│   │   ├── fiber/
│   │   └── gin/
│   │       └── main.go
│   ├── oauth/
│   └── README.md
├── internal/
│   ├── api/
│   │   ├── docs/
│   │   │   ├── api/
│   │   │   │   ├── oauth/
│   │   │   │   │   ├── apple.go
│   │   │   │   │   ├── discord.go
│   │   │   │   │   ├── facebook.go
│   │   │   │   │   ├── github.go
│   │   │   │   │   ├── google.go
│   │   │   │   │   └── microsoft.go
│   │   │   │   ├── deactivateUser.go
│   │   │   │   ├── emailVerification.go
│   │   │   │   ├── forgetPassword.go
│   │   │   │   ├── getMe.go
│   │   │   │   ├── login.go
│   │   │   │   ├── logout.go
│   │   │   │   ├── magicLink.go
│   │   │   │   ├── refreshToken.go
│   │   │   │   ├── register.go
│   │   │   │   ├── resetPassword.go
│   │   │   │   ├── sendPhoneVerification.go
│   │   │   │   ├── twoFactor.go
│   │   │   │   ├── updateProfile.go
│   │   │   │   └── verifyPhone.go
│   │   │   ├── definations/
│   │   │   │   ├── error.go
│   │   │   │   ├── request.go
│   │   │   │   ├── response.go
│   │   │   │   └── user.go
│   │   │   ├── README.md
│   │   │   ├── server.go
│   │   │   └── swagger.go
│   │   ├── handlers/
│   │   │   ├── errors/
│   │   │   │   └── responseErrors.go
│   │   │   ├── oauth/
│   │   │   │   ├── apple.go
│   │   │   │   ├── discord.go
│   │   │   │   ├── facebook.go
│   │   │   │   ├── github.go
│   │   │   │   ├── google.go
│   │   │   │   ├── linkedin.go
│   │   │   │   ├── microsoft.go
│   │   │   │   └── twitter.go
│   │   │   ├── common.go
│   │   │   ├── core.go
│   │   │   ├── deactivateProfile.go
│   │   │   ├── forgetPassword.go
│   │   │   ├── getCsrfToken.go
│   │   │   ├── getMe.go
│   │   │   ├── login.go
│   │   │   ├── logout.go
│   │   │   ├── magicLink.go
│   │   │   ├── refreshToken.go
│   │   │   ├── register.go
│   │   │   ├── resetPassword.go
│   │   │   ├── sendEmailVerification.go
│   │   │   ├── sendPhoneVerification.go
│   │   │   ├── twoFactor.go
│   │   │   ├── update.profile.go
│   │   │   ├── updateProfile.go
│   │   │   ├── validations.go
│   │   │   ├── verifyEmail.go
│   │   │   └── verifyPhone.go
│   │   ├── middlewares/
│   │   │   ├── auth.go
│   │   │   ├── csrf.go
│   │   │   ├── middleware.go
│   │   │   ├── rateLimiter.go
│   │   │   └── recaptcha.go
│   │   └── api.go
│   ├── caches/
│   │   └── redisClient.go
│   ├── database/
│   │   └── dbClient.go
│   ├── external/
│   │   └── httpClient.go
│   ├── hooks/
│   │   └── hooks.go
│   ├── logger/
│   │   └── logger.go
│   ├── notifications/
│   │   ├── email/
│   │   │   ├── templates/
│   │   │   │   ├── reset_password.html
│   │   │   │   ├── verify_email.html
│   │   │   │   └── welcome.html
│   │   │   └── email_sender.go
│   │   └── sms/
│   │       └── sms_sender.go
│   ├── ratelimiter/
│   │   ├── memoryRateLimiter.go
│   │   ├── rateLimiter.go
│   │   └── redisRateLimiter.go
│   ├── recaptcha/
│   │   ├── cloudflare.go
│   │   ├── google.go
│   │   └── recaptcha.go
│   ├── repositories/
│   │   ├── mongodb/
│   │   ├── mysql/
│   │   ├── postgres/
│   │   │   ├── factory.go
│   │   │   ├── tokenRepositories.go
│   │   │   └── userRepositories.go
│   │   └── factory.go
│   ├── schemas/
│   │   └── req.schema.go
│   ├── tokens/
│   │   └── tokenManager.go
│   └── utils/
│       ├── getIp.go
│       ├── http.go
│       ├── pkce.go
│       └── url.go
├── pkg/
│   ├── auth/
│   │   ├── auth.go
│   │   ├── builder.go
│   │   └── types.go
│   ├── config/
│   │   ├── auth.go
│   │   ├── common.type.go
│   │   ├── config.go
│   │   ├── constants.go
│   │   ├── notification.go
│   │   ├── providers.go
│   │   ├── security.go
│   │   └── storage.go
│   ├── interfaces/
│   │   ├── email.go
│   │   ├── repositoryInterface.go
│   │   ├── security.go
│   │   ├── sms.go
│   │   └── tokenManager.go
│   └── models/
│       ├── common.go
│       └── models.go
├── tests/
│   ├── benchmarks/
│   │   ├── api/
│   │   │   └── handlers_benchmark_test.go
│   │   └── repositories/
│   │       └── repository_benchmark_test.go
│   ├── integration/
│   │   ├── api/
│   │   │   └── auth_integration_test.go
│   │   └── repositories/
│   │       └── database_integration_test.go
│   ├── unit/
│   │   ├── api/
│   │   │   └── handlers/
│   │   │       ├── auth_test.go
│   │   │       ├── getMe_test.go
│   │   │       ├── login_test.go
│   │   │       ├── logout_test.go
│   │   │       ├── refreshToken_test.go
│   │   │       ├── register_test.go
│   │   │       └── test_utils.go
│   │   ├── hooks/
│   │   │   └── hooks_test.go
│   │   ├── repositories/
│   │   │   ├── postgres/
│   │   │   │   └── factory_test.go
│   │   │   └── user_repository_test.go
│   │   ├── tokens/
│   │   │   └── token_manager_test.go
│   │   ├── build.config_test.go
│   │   ├── goauth_test.go
│   │   ├── integration_test.go
│   │   └── test_config.go
│   ├── README.md
│   ├── test_config.go
│   └── test_utils.go
├── LICENSE
├── README.md
├── folderstructure.md
├── go.mod
├── go.sum
└── makefile
```

---

## 🛠️ Generated with foldermd

**Configuration used:**
- Include files: `true`
- Include content: `false`
- Max depth: `-1`
- Show hidden: `false`
- Ignore patterns: `.git, .DS_Store, node_modules, *.log`

*This README was automatically generated. Consider customizing it for your project!*
