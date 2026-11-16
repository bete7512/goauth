import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";
import { appName, repositoryUrl } from "./shared";

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="brand-wordmark inline-flex items-center gap-2 text-[17px]">
          <img src="/logo.svg" alt="" width={26} height={26} />
          <span>
            {appName}
            <span className="brand-wordmark-dot">.</span>
          </span>
        </span>
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
