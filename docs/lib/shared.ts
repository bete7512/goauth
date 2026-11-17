import { siteUrl } from "./site.mjs";

export { siteUrl, indexable } from "./site.mjs";
export const appName = "GoAuth";
export const siteTitle = "GoAuth — Authentication library for Go (Golang)";
export const siteDescription =
  "Open-source authentication library for Go. Add login, JWT, sessions, OAuth2, passkeys, 2FA, RBAC, organizations, OIDC and SAML to your own Go server.";
export const siteKeywords = [
  "golang authentication",
  "go authentication library",
  "goauth",
];
export const gitConfig = { user: "bete7512", repo: "go-auth", branch: "main" };
export const repositoryUrl = `https://github.com/${gitConfig.user}/${gitConfig.repo}`;
export const modulePath = "github.com/bete7512/goauth";
export const goPackageUrl = `https://pkg.go.dev/${modulePath}`;
export const publisher = {
  "@type": "Organization",
  name: appName,
  url: siteUrl,
  logo: `${siteUrl}/logo.svg`,
  sameAs: [repositoryUrl, goPackageUrl],
};
