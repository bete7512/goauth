# go-auth Documentation

A modern, comprehensive documentation site for the go-auth authentication library built with Next.js, Tailwind CSS, and shadcn/ui.

## Features

- 📚 **Comprehensive Documentation** - Complete guides for installation, configuration, and usage
- 🎨 **Modern UI** - Beautiful, responsive design with dark mode support
- ⚡ **Fast Performance** - Built with Next.js 15 and optimized for speed
- 📱 **Mobile Friendly** - Responsive design that works on all devices
- 🔍 **Search Ready** - Structured for easy navigation and search
- 🎯 **Framework Support** - Documentation for all supported Go web frameworks

## Getting Started

### Prerequisites

- Node.js 18+ 
- pnpm (recommended) or npm

### Installation

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Start the development server:
   ```bash
   pnpm dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Available Scripts

- `pnpm dev` - Start development server with Turbopack
- `pnpm build` - Build for production
- `pnpm start` - Start production server
- `pnpm lint` - Run ESLint

## Documentation Structure

```
docs/
├── src/
│   ├── app/
│   │   ├── page.tsx              # Home page
│   │   ├── installation/         # Installation guide
│   │   ├── quickstart/           # Quick start guide
│   │   ├── configuration/        # Configuration reference
│   │   ├── frameworks/           # Framework-specific guides
│   │   ├── features/             # Feature documentation
│   │   ├── api/                  # API reference
│   │   └── examples/             # Code examples
│   ├── components/
│   │   └── ui/                   # shadcn/ui components
│   └── lib/
│       └── utils.ts              # Utility functions
├── public/                       # Static assets
└── package.json
```

## Technologies Used

- **Next.js 15** - React framework with App Router
- **Tailwind CSS 4** - Utility-first CSS framework
- **shadcn/ui** - Beautiful, accessible UI components
- **TypeScript** - Type-safe JavaScript
- **Lucide React** - Beautiful icons
- **Radix UI** - Accessible UI primitives

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally with `pnpm dev`
5. Submit a pull request

## Building for Production

```bash
pnpm build
pnpm start
```

The built site will be optimized for production with:
- Static generation where possible
- Optimized images and assets
- Minified CSS and JavaScript
- SEO optimizations

## Deployment

This documentation site can be deployed to:
- Vercel (recommended)
- Netlify
- Any static hosting service

The site is fully static and can be served from any web server.

## License

This documentation is part of the go-auth project and follows the same license.
