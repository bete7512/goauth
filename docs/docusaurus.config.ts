import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: "GoAuth",
  tagline:
    "Modular, framework-agnostic authentication for Go - build only what you need",
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
          routeBasePath: "docs",
          path: "docs",
        },
        blog: {
          showReadingTime: true,
          editUrl: "https://github.com/your-org/goauth/tree/main/blog/",
        },
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Replace with your project's social card
    image: "img/goauth-social-card.jpg",

    // Announcement Banner
    announcementBar: {
      id: "goauth-modular-banner",
      content:
        '🧩 GoAuth v2.0 - Now with modular architecture! Build only what you need. <a href="/docs/intro" target="_blank" rel="noopener noreferrer">Learn More →</a>',
      backgroundColor: "#667eea",
      textColor: "#ffffff",
      isCloseable: true,
    },

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
          to: "/docs/api/endpoints",
          position: "left",
          label: "API",
        },
        {
          to: "/docs/showcase",
          position: "left",
          label: "Showcase",
        },
        {
          to: "/blog",
          label: "Blog",
          position: "left",
        },
        {
          to: "/docs/community",
          position: "left",
          label: "Community",
        },
        {
          type: "dropdown",
          label: "v1.0.0",
          position: "right",
          className: "version-dropdown",
          items: [
            {
              label: "v1.0.0 (Latest)",
              href: "https://github.com/your-org/goauth/releases/tag/v1.0.0",
            },
            {
              label: "v0.9.0",
              href: "https://github.com/your-org/goauth/releases/tag/v0.9.0",
            },
            {
              label: "View all releases",
              href: "https://github.com/your-org/goauth/releases",
            },
          ],
        },
        {
          type: "localeDropdown",
          position: "right",
        },
        {
          href: "https://github.com/bete7512/goauth",
          position: "right",
          className: "github-link",
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
              label: "Introduction",
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
          title: "Modules",
          items: [
            {
              label: "Core Module",
              to: "/docs/modules/core",
            },
            {
              label: "Notification Module",
              to: "/docs/modules/notification",
            },
            {
              label: "All Modules",
              to: "/docs/intro#available-modules",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/bete7512/goauth",
            },
            {
              label: "Issues",
              href: "https://github.com/bete7512/goauth/issues",
            },
            {
              label: "Discussions",
              href: "https://github.com/bete7512/goauth/discussions",
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
