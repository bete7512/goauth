import { source } from "@/lib/source";

export const dynamic = "force-static";

export async function GET() {
  const pages = await Promise.all(
    source
      .getPages()
      .map(
        async (page) =>
          `# ${page.data.title}\n\n${await page.data.getText("processed")}`,
      ),
  );
  return new Response(pages.join("\n\n"), {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Robots-Tag": "noindex",
    },
  });
}
