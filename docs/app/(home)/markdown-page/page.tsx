import { pageSource } from "@/lib/source";
import { getMDXComponents } from "@/components/mdx";

export const metadata = {
  title: "Markdown page example",
  robots: { index: false, follow: true },
};
export default function MarkdownPage() {
  const page = pageSource.getPage(["markdown-page"])!;
  const MDX = page.data.body;
  return (
    <main className="prose mx-auto w-full max-w-4xl px-5 py-14">
      <h1>{page.data.title}</h1>
      <MDX components={getMDXComponents()} />
    </main>
  );
}
