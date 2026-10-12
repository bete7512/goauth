import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-[70vh] flex-col items-center justify-center gap-5 px-5 text-center">
      <p className="text-sm text-fd-muted-foreground">404</p>
      <h1 className="text-3xl font-bold">Page not found</h1>
      <p className="text-fd-muted-foreground">
        This documentation page could not be found.
      </p>
      <Link
        href="/docs"
        className="rounded-lg bg-fd-primary px-5 py-3 text-fd-primary-foreground"
      >
        Browse the documentation
      </Link>
    </main>
  );
}
