import { notFound } from "next/navigation";
import { BlogList } from "@/components/blog-list";
import { posts } from "@/lib/source";
import { pageMetadata } from "@/lib/metadata";

const tags = () => [...new Set(posts().flatMap((post) => post.data.tags))];
export const generateStaticParams = () => tags().map((tag) => ({ tag }));
export async function generateMetadata({
  params,
}: PageProps<"/blog/tags/[tag]">) {
  const { tag } = await params;
  if (!tags().includes(tag)) notFound();
  return pageMetadata(
    `${tag} articles`,
    `GoAuth articles about ${tag}.`,
    `/blog/tags/${tag}`,
  );
}
export default async function Tag({ params }: PageProps<"/blog/tags/[tag]">) {
  const { tag } = await params;
  if (!tags().includes(tag)) notFound();
  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-14">
      <h1 className="mb-8 text-3xl font-bold">Articles about {tag}</h1>
      <BlogList tag={tag} />
    </main>
  );
}
