import { docs, blog, pages } from "collections/server";
import { loader } from "fumadocs-core/source";

export const source = loader({
  baseUrl: "/docs",
  source: docs.toFumadocsSource(),
});
export const blogSource = loader({
  baseUrl: "/blog",
  source: blog.toFumadocsSource(),
});
export const pageSource = loader({
  baseUrl: "/",
  source: pages.toFumadocsSource(),
});
export const posts = () =>
  blogSource
    .getPages()
    .sort((a, b) => (b.data.date ?? "").localeCompare(a.data.date ?? ""));
export const allPages = () => [
  ...source.getPages(),
  ...blogSource.getPages(),
  ...pageSource.getPages(),
];
