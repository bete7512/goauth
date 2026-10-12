// Canonical production origin. SITE_URL can override it at build time.
const configured = process.env.SITE_URL || "https://goauth.beteg.dev";
const parsed = new URL(configured);
if (
  !["http:", "https:"].includes(parsed.protocol) ||
  parsed.pathname !== "/" ||
  parsed.search ||
  parsed.hash ||
  parsed.username ||
  parsed.password
) {
  throw new Error(
    "SITE_URL must be an absolute HTTP(S) origin, without a path, query, or credentials.",
  );
}
if (
  parsed.protocol !== "https:" ||
  ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
) {
  throw new Error("SITE_URL must be the public HTTPS production origin.");
}

export const siteUrl = parsed.origin;
export const indexable =
  process.env.NODE_ENV !== "development" &&
  process.env.VERCEL_ENV !== "preview";
