import type { MetadataRoute } from "next";
import { indexable, siteUrl } from "@/lib/shared";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: indexable
      ? { userAgent: "*", allow: "/", disallow: ["/api/"] }
      : { userAgent: "*", disallow: "/" },
    ...(indexable ? { sitemap: `${siteUrl}/sitemap.xml` } : {}),
  };
}
