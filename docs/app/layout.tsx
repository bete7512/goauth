import type { Metadata } from "next";
import { RootProvider } from "fumadocs-ui/provider/next";
import { siteTitle, siteDescription, siteUrl } from "@/lib/shared";
import "./global.css";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: siteTitle, template: "%s | GoAuth" },
  description: siteDescription,
  applicationName: "GoAuth",
  icons: { icon: "/logo.svg" },
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
