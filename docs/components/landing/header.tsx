"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowUpRight, GitFork, Menu, X } from "lucide-react";
import { ThemeSwitch } from "fumadocs-ui/layouts/shared/slots/theme-switch";
import { repositoryUrl } from "@/lib/shared";

export function LandingHeader() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    function escape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, []);
  return (
    <header className="landing-header landing-container">
      <Link href="/" className="wordmark" aria-label="GoAuth home">
        <img src="/logo.svg" alt="" width={34} height={34} />
        GoAuth<span className="wordmark-dot">.</span>
      </Link>
      <nav
        className={`landing-nav ${open ? "is-open" : ""}`}
        id="landing-nav"
        aria-label="Main navigation"
        onClick={() => setOpen(false)}
      >
        <Link href="/docs">Documentation</Link>
        <a href="#modules">Modules</a>
        <Link href="/blog">Blog</Link>
        <a href={repositoryUrl} className="mobile-github">
          GitHub <ArrowUpRight size={14} />
        </a>
      </nav>
      <div className="header-actions">
        <ThemeSwitch />
        <a
          href={repositoryUrl}
          className="github-link"
          aria-label="GoAuth on GitHub"
        >
          <GitFork size={18} />
          <span>Star on GitHub</span>
          <ArrowUpRight size={14} />
        </a>
        <button
          className="icon-button menu-toggle"
          type="button"
          aria-label={open ? "Close navigation" : "Open navigation"}
          aria-expanded={open}
          aria-controls="landing-nav"
          onClick={() => setOpen(!open)}
        >
          {open ? <X size={22} /> : <Menu size={22} />}
        </button>
      </div>
    </header>
  );
}
