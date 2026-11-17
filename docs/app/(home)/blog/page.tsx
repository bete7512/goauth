import { BlogList } from "@/components/blog-list";
import { pageMetadata } from "@/lib/metadata";

export const metadata = pageMetadata(
  "Go authentication guides and articles",
  "How-to guides for authentication in Go: passkeys, JWT refresh tokens, OpenID Connect, security and performance, written by the GoAuth maintainers.",
  "/blog",
);

export default function Blog() {
  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-14">
      <h1 className="mb-3 text-4xl font-bold">GoAuth Blog</h1>
      <p className="mb-10 text-lg text-fd-muted-foreground">
        Authentication, architecture, and building with GoAuth.
      </p>
      <BlogList />
    </main>
  );
}
