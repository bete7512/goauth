import Link from "next/link";
import { posts } from "@/lib/source";
import { pageMetadata } from "@/lib/metadata";

export const metadata = pageMetadata(
  "Blog topics",
  "Browse GoAuth articles by topic.",
  "/blog/tags",
);
export default function Tags() {
  const tags = [...new Set(posts().flatMap((post) => post.data.tags))].sort();
  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-14">
      <h1 className="mb-8 text-3xl font-bold">Blog topics</h1>
      <div className="flex flex-wrap gap-3">
        {tags.map((tag) => (
          <Link
            key={tag}
            href={`/blog/tags/${tag}`}
            className="rounded-lg border px-4 py-3 hover:bg-fd-accent"
          >
            {tag}
          </Link>
        ))}
      </div>
    </main>
  );
}
