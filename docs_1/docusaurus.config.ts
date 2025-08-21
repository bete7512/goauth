import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: "GoAuth",
  tagline:
    "A comprehensive Go authentication library with OAuth, JWT, and security features",
  favicon: "img/favicon.ico",

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: "https://your-goauth-site.example.com",
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/",

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "your-org", // Usually your GitHub org/user name.
  projectName: "goauth", // Usually your repo name.

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/your-org/goauth/tree/main/docs/",
        },
        blog: false, // Disable blog since we don't have one
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: "img/goauth-social-card.jpg",
    navbar: {
      title: "GoAuth",
      logo: {
        alt: "GoAuth Logo",
        src: "img/logo.svg",
      },
      items: [
        {
          type: "docSidebar",
          sidebarId: "tutorialSidebar",
          position: "left",
          label: "Docs",
        },
        {
          type: "dropdown",
          label: "Features",
          position: "left",
          items: [
            {
              label: "OAuth",
              to: "/docs/features/oauth",
            },
            {
              label: "JWT",
              to: "/docs/features/jwt",
            },
            {
              label: "Two-Factor Auth",
              to: "/docs/features/two-factor",
            },
            {
              label: "Security",
              to: "/docs/features/security",
            },
          ],
        },
        {
          type: "dropdown",
          label: "Frameworks",
          position: "left",
          items: [
            {
              label: "Gin",
              to: "/docs/frameworks/gin",
            },
          ],
        },
        {
          href: "https://github.com/your-org/goauth",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Documentation",
          items: [
            {
              label: "Getting Started",
              to: "/docs/intro",
            },
            {
              label: "Installation",
              to: "/docs/installation",
            },
            {
              label: "Quick Start",
              to: "/docs/quickstart",
            },
          ],
        },
        {
          title: "Features",
          items: [
            {
              label: "OAuth",
              to: "/docs/features/oauth",
            },
            {
              label: "JWT",
              to: "/docs/features/jwt",
            },
            {
              label: "Two-Factor Auth",
              to: "/docs/features/two-factor",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/your-org/goauth",
            },
            {
              label: "Issues",
              href: "https://github.com/your-org/goauth/issues",
            },
            {
              label: "Discussions",
              href: "https://github.com/your-org/goauth/discussions",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} GoAuth Project. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["go"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
