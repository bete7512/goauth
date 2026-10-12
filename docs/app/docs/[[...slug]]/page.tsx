import { notFound } from "next/navigation";
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  MarkdownCopyButton,
  ViewOptionsPopover,
} from "fumadocs-ui/layouts/docs/page";
import { getMDXComponents } from "@/components/mdx";
import { StructuredData } from "@/components/structured-data";
import { source } from "@/lib/source";
import { pageMetadata } from "@/lib/metadata";
import { repositoryUrl, gitConfig, siteUrl } from "@/lib/shared";

export default async function Page({ params }: PageProps<"/docs/[[...slug]]">) {
  const page = source.getPage((await params).slug);
  if (!page) notFound();
  const MDX = page.data.body;
  return (
    <DocsPage toc={page.data.toc} full={page.data.full}>
      <StructuredData
        data={{
          "@context": "https://schema.org",
          "@type": "TechArticle",
          headline: page.data.title,
          description: page.data.description,
          url: `${siteUrl}${page.url}`,
          inLanguage: "en",
          isPartOf: { "@type": "WebSite", name: "GoAuth", url: siteUrl },
        }}
      />
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      <div className="mb-6 flex flex-wrap items-center gap-2 border-b pb-6">
        <MarkdownCopyButton
          markdownUrl={`/llms.mdx/docs/${[...page.slugs, "content.md"].join("/")}`}
        />
        <ViewOptionsPopover
          markdownUrl={`/llms.mdx/docs/${[...page.slugs, "content.md"].join("/")}`}
          githubUrl={`${repositoryUrl}/blob/${gitConfig.branch}/docs/${page.data.sourcePath}`}
        />
      </div>
      <DocsBody>
        <MDX components={getMDXComponents()} />
      </DocsBody>
      <a
        className="mt-6 text-sm text-fd-muted-foreground underline underline-offset-4"
        href={`${repositoryUrl}/edit/${gitConfig.branch}/docs/${page.data.sourcePath}`}
      >
        Edit this page on GitHub
      </a>
    </DocsPage>
  );
}

export const generateStaticParams = () => source.generateParams();

export async function generateMetadata({
  params,
}: PageProps<"/docs/[[...slug]]">) {
  const page = source.getPage((await params).slug);
  if (!page) notFound();
  return pageMetadata(page.data.title, page.data.description ?? "", page.url);
}
