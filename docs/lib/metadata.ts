import type { Metadata } from "next";
import { appName, indexable, siteKeywords, siteUrl } from "./shared";

export type PageMetadataOptions = {
  /** Publication date; marks the page as an article. */
  articleDate?: string;
  /** Last change, from the source file's last commit. */
  modified?: string;
  /** Search phrases the page answers, merged with the site-wide ones. */
  keywords?: string[];
};

export function pageMetadata(
  title: string,
  description: string,
  path: string,
  { articleDate, modified, keywords = [] }: PageMetadataOptions = {},
): Metadata {
  const url = `${siteUrl}${path === "/" ? "" : path}`;
  const image = `${siteUrl}/og/image.png?title=${encodeURIComponent(title)}`;
  return {
    title,
    description,
    keywords: [...new Set([...keywords, ...siteKeywords])],
    alternates: { canonical: url },
    robots: { index: indexable, follow: true },
    openGraph: {
      title,
      description,
      url,
      siteName: appName,
      locale: "en_US",
      type: articleDate ? "article" : "website",
      ...(articleDate ? { publishedTime: articleDate } : {}),
      ...(articleDate && modified ? { modifiedTime: modified } : {}),
      images: [{ url: image, width: 1200, height: 630, alt: title }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [image],
    },
  };
}
