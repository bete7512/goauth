import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { appName, repositoryUrl } from "./shared";

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <img src="/logo.svg" alt="" width={26} height={26} />
          {appName}
        </>
      ),
    },
    githubUrl: repositoryUrl,
    links: [
      { text: "Documentation", url: "/docs", active: "nested-url" },
      { text: "API Reference", url: "/docs/api/endpoints" },
      { text: "Blog", url: "/blog", active: "nested-url" },
      { text: "Community", url: "/docs/community" },
    ],
  };
}
