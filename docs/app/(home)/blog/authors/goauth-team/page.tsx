import { BlogList } from "@/components/blog-list";
import { pageMetadata } from "@/lib/metadata";

export const metadata = pageMetadata(
  "GoAuth Team",
  "Articles from the GoAuth development team.",
  "/blog/authors/goauth-team",
);
export default function Author() {
  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-14">
      <h1 className="mb-3 text-3xl font-bold">GoAuth Team</h1>
      <p className="mb-8 text-fd-muted-foreground">GoAuth Development Team</p>
      <BlogList author="goauth-team" />
    </main>
  );
}
