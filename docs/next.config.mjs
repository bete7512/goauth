import { createMDX } from "fumadocs-mdx/next";

const withMDX = createMDX();

export default withMDX({
  // Keep the docs dev server from generating repository instruction files.
  agentRules: false,
  reactStrictMode: true,
  poweredByHeader: false,
  async redirects() {
    return [
      { source: "/blog/archive", destination: "/blog", permanent: true },
      {
        source: "/blog/authors",
        destination: "/blog/authors/goauth-team",
        permanent: true,
      },
      { source: "/docs/index", destination: "/docs", permanent: true },
      {
        source: "/docs/api/auth",
        destination: "/docs/api/api-auth",
        permanent: true,
      },
    ];
  },
});
