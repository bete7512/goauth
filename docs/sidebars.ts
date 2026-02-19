import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

/**
 * GoAuth Documentation Sidebar
 */
const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    "index",
    "intro",
    "installation",
    "quickstart",
    
    {
      type: "category",
      label: "Modules",
      collapsed: false,
      description: "GoAuth's modular architecture",
      items: [
        "modules/core",
        {
          type: "category",
          label: "Authentication",
          collapsed: false,
          items: [
            "modules/session",
            "modules/stateless",
          ],
        },
        "modules/notification",
        "modules/twofactor",
        "modules/oauth",
        "modules/admin",
        "modules/audit",
        "modules/captcha",
        "modules/csrf",
        "modules/magiclink",
      ],
    },
    
    {
      type: "category",
      label: "API Reference",
      items: ["api/endpoints"],
    },
    
    "showcase",
    "community",
  ],

  apiSidebar: ["api/endpoints"],
};

export default sidebars;
