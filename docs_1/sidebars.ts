import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  // By default, Docusaurus generates a sidebar from the docs folder structure
  tutorialSidebar: [
    "index",
    "intro",
    "installation",
    "quickstart",
    {
      type: "category",
      label: "Getting Started",
      items: [
        "getting-started/basic-auth",
        "getting-started/oauth-setup",
        "getting-started/custom-storage",
      ],
    },
    {
      type: "category",
      label: "Features",
      items: [
        "features/oauth",
        "features/jwt",
        "features/two-factor",
        "features/rate-limiting",
        "features/recaptcha",
        "features/security",
      ],
    },
    {
      type: "category",
      label: "Frameworks",
      items: ["frameworks/gin"],
    },
    {
      type: "category",
      label: "API Reference",
      items: ["api/endpoints"],
    },
    {
      type: "category",
      label: "Configuration",
      items: ["configuration/auth"],
    },
    {
      type: "category",
      label: "Examples",
      items: ["examples/basic-auth"],
    },
  ],

  // API Documentation Sidebar
  apiSidebar: ["api/endpoints"],


};

export default sidebars;
