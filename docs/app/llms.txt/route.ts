import { source } from "@/lib/source";
import { siteUrl, siteDescription } from "@/lib/shared";

export const dynamic = "force-static";
export function GET() {
  const links = source
    .getPages()
    .map(
      (page) =>
        `- [${page.data.title}](${siteUrl}${page.url}): ${page.data.description ?? ""}`,
    );
  return new Response(
    `# GoAuth\n\n> ${siteDescription}\n\n## Documentation\n\n${links.join("\n")}\n`,
    { headers: { "Content-Type": "text/plain; charset=utf-8" } },
  );
}
