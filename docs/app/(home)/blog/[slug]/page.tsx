import Link from "next/link";
import { notFound } from "next/navigation";
import { getMDXComponents } from "@/components/mdx";
import { StructuredData } from "@/components/structured-data";
import { blogSource } from "@/lib/source";
import { pageMetadata } from "@/lib/metadata";
import { siteUrl } from "@/lib/shared";

export const generateStaticParams = () =>
  blogSource.getPages().map((page) => ({ slug: page.slugs[0] }));

export async function generateMetadata({ params }: PageProps<"/blog/[slug]">) {
  const page = blogSource.getPage([(await params).slug]);
  if (!page) notFound();
  return pageMetadata(
    page.data.title,
    page.data.description ?? "",
    page.url,
    page.data.date,
  );
}

export default async function Post({ params }: PageProps<"/blog/[slug]">) {
  const page = blogSource.getPage([(await params).slug]);
  if (!page) notFound();
  const MDX = page.data.body;
  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-12">
      <article>
        <StructuredData
          data={{
            "@context": "https://schema.org",
            "@type": "BlogPosting",
            headline: page.data.title,
            description: page.data.description,
            datePublished: page.data.date,
            author: { "@type": "Organization", name: "GoAuth Team" },
            mainEntityOfPage: `${siteUrl}${page.url}`,
            image: `${siteUrl}/og/image.png?title=${encodeURIComponent(page.data.title)}`,
          }}
        />
        <Link
          href="/blog"
          className="text-sm text-fd-muted-foreground hover:underline"
        >
          ← All articles
        </Link>
        <h1 className="mt-6 mb-4 text-3xl font-bold sm:text-4xl">
          {page.data.title}
        </h1>
        <p className="mb-8 text-sm text-fd-muted-foreground">
          <time dateTime={page.data.date}>{page.data.date}</time> ·{" "}
          <Link href="/blog/authors/goauth-team">GoAuth Team</Link>
        </p>
        <div className="prose max-w-none">
          <MDX components={getMDXComponents()} />
        </div>
        <div className="mt-8 flex flex-wrap gap-2 border-t pt-6">
          {page.data.tags.map((tag) => (
            <Link
              key={tag}
              href={`/blog/tags/${tag}`}
              className="rounded-md bg-fd-secondary px-3 py-1 text-sm"
            >
              {tag}
            </Link>
          ))}
        </div>
      </article>
    </main>
  );
}
