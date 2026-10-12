import type { MetadataRoute } from "next";
import { allPages, posts } from "@/lib/source";
import { indexable, siteUrl } from "@/lib/shared";

export default function sitemap(): MetadataRoute.Sitemap {
  if (!indexable) return [];
  return [
    { url: siteUrl, priority: 1 },
    { url: `${siteUrl}/blog`, priority: 0.6 },
    { url: `${siteUrl}/blog/tags`, priority: 0.4 },
    { url: `${siteUrl}/blog/authors/goauth-team`, priority: 0.4 },
    ...[...new Set(posts().flatMap((post) => post.data.tags))].map((tag) => ({
      url: `${siteUrl}/blog/tags/${tag}`,
      priority: 0.4,
    })),
    ...allPages()
      .filter((page) => page.url !== "/markdown-page")
      .map((page) => ({ url: `${siteUrl}${page.url}`, priority: 0.8 })),
  ];
}
