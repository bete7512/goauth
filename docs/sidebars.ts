import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

/**
 * GoAuth Documentation Sidebar
 * 
 * Clean, modular documentation structure reflecting the new architecture.
 */
const sidebars: SidebarsConfig = {
  // Main documentation sidebar
  tutorialSidebar: [
    // Overview and Getting Started
    "index",
    "intro",
    "installation",
    "quickstart",
    
    // Modules Section - The heart of GoAuth
    {
      type: "category",
      label: "Modules",
      collapsed: false,
      description: "GoAuth's modular architecture - build only what you need",
      items: [
        "modules/core",
        "modules/notification",
        // Add more modules here as documentation is completed:
        // "modules/twofactor",
        // "modules/oauth",
        // "modules/ratelimiter",
        // "modules/captcha",
        // "modules/csrf",
        // "modules/admin",
        // "modules/magiclink",
      ],
    },
    
    // API Reference
    {
      type: "category",
      label: "API Reference",
      items: ["api/endpoints"],
    },
    
    // Community and Showcase
    "showcase",
    "community",
  ],

  // Optional: Separate API sidebar if needed
  apiSidebar: ["api/endpoints"],
};

export default sidebars;
