import type { Metadata } from "next";
import { appName, indexable, siteUrl } from "./shared";

export function pageMetadata(
  title: string,
  description: string,
  path: string,
  articleDate?: string,
): Metadata {
  const url = `${siteUrl}${path === "/" ? "" : path}`;
  return {
    title,
    description,
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
      images: [
        {
          url: `${siteUrl}/og/image.png?title=${encodeURIComponent(title)}`,
          width: 1200,
          height: 630,
          alt: title,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [`${siteUrl}/og/image.png?title=${encodeURIComponent(title)}`],
    },
  };
}
