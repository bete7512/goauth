import Link from "next/link";
import { posts } from "@/lib/source";

export function BlogList({ tag, author }: { tag?: string; author?: string }) {
  const items = posts().filter(
    (post) =>
      (!tag || post.data.tags.includes(tag)) &&
      (!author || post.data.authors.includes(author)),
  );
  return (
    <div className="grid gap-5">
      {items.map((post) => (
        <article
          key={post.url}
          className="rounded-xl border bg-fd-card p-6 sm:p-8"
        >
          <p className="mb-3 text-sm text-fd-muted-foreground">
            <time dateTime={post.data.date}>{post.data.date}</time> · GoAuth
            Team
          </p>
          <h2 className="mb-3 text-xl font-semibold">
            <Link href={post.url} className="hover:underline">
              {post.data.title}
            </Link>
          </h2>
          <p className="mb-4 leading-relaxed text-fd-muted-foreground">
            {post.data.description}
          </p>
          <div className="flex flex-wrap gap-2">
            {post.data.tags.map((value) => (
              <Link
                key={value}
                href={`/blog/tags/${value}`}
                className="rounded-md bg-fd-secondary px-2 py-1 text-xs hover:bg-fd-accent"
              >
                {value}
              </Link>
            ))}
          </div>
        </article>
      ))}
    </div>
  );
}
