import Link from "next/link";
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Braces,
  Check,
  Database,
  Fingerprint,
  GitFork,
  Layers3,
  LockKeyhole,
  Radio,
  ShieldCheck,
} from "lucide-react";
import { LandingHeader } from "@/components/landing/header";
import { CopyButton } from "@/components/landing/copy-button";
import { ModuleBuilder } from "@/components/landing/module-builder";
import { StructuredData } from "@/components/structured-data";
import { pageMetadata } from "@/lib/metadata";
import {
  siteTitle,
  siteDescription,
  siteUrl,
  repositoryUrl,
} from "@/lib/shared";

export const metadata = {
  ...pageMetadata(siteTitle, siteDescription, "/"),
  title: { absolute: siteTitle },
};
const install = "go get github.com/bete7512/goauth";

export default function HomePage() {
  return (
    <>
      <a className="landing-skip" href="#main-content">
        Skip to content
      </a>
      <LandingHeader />
      <main id="main-content">
        <StructuredData
          data={{
            "@context": "https://schema.org",
            "@type": "SoftwareSourceCode",
            name: "GoAuth",
            description: siteDescription,
            url: siteUrl,
            codeRepository: repositoryUrl,
            programmingLanguage: "Go",
            license: `${repositoryUrl}/blob/main/LICENSE`,
          }}
        />
        <section
          className="hero landing-container"
          aria-labelledby="hero-title"
        >
          <div className="hero-copy">
            <p className="eyebrow">
              <span className="status-dot" /> Open source. Native Go. Yours.
            </p>
            <h1 id="hero-title">
              Your app.
              <br />
              <span>Your auth.</span>
              <br />
              Your rules.
            </h1>
            <p className="hero-description">
              Authentication that belongs in your codebase. Add sessions,
              passkeys, OAuth, two-factor, and more with a modular Go library
              built around your application.
            </p>
            <div className="hero-actions">
              <Link href="/docs/quickstart" className="landing-button primary">
                Start building <ArrowRight size={17} />
              </Link>
              <Link href="/docs" className="text-link">
                Read the docs <ArrowUpRight size={16} />
              </Link>
            </div>
            <div className="install-command">
              <span aria-hidden>$</span>
              <code>{install}</code>
              <CopyButton value={install} label="Copy install command" />
            </div>
          </div>
          <div
            className="hero-blueprint"
            role="img"
            aria-label="GoAuth runs inside your Go application, connecting your chosen authentication modules to your own storage."
          >
            <div className="blueprint-top">
              <span>YOUR APPLICATION</span>
              <span className="blueprint-index">FIG. 01</span>
            </div>
            <div className="blueprint-content" aria-hidden>
              <div className="app-node">
                <Braces size={19} />
                <span>
                  your-app<span className="mono">.go</span>
                </span>
                <span className="app-indicator" />
              </div>
              <div className="vertical-connector">
                <span>import</span>
              </div>
              <div className="auth-node">
                <div className="auth-node-icon">
                  <ShieldCheck size={34} strokeWidth={1.4} />
                </div>
                <div>
                  <strong>GoAuth</strong>
                  <span>One library. Your composition.</span>
                </div>
                <span className="auth-node-plus">+</span>
              </div>
              <div className="module-connectors">
                <span />
                <span />
                <span />
              </div>
              <div className="blueprint-modules">
                <div>
                  <LockKeyhole size={20} />
                  <strong>Sessions / JWT</strong>
                  <span>Your strategy</span>
                </div>
                <div>
                  <Fingerprint size={20} />
                  <strong>OAuth + 2FA</strong>
                  <span>Your modules</span>
                </div>
                <div>
                  <Layers3 size={20} />
                  <strong>Organizations</strong>
                  <span>Your structure</span>
                </div>
              </div>
              <div className="storage-connector" />
              <div className="storage-node">
                <Database size={17} />
                <span>Your storage</span>
                <span className="storage-databases">
                  PostgreSQL · MySQL · SQLite
                </span>
              </div>
            </div>
            <div className="blueprint-bottom">
              <span>
                <Check size={13} /> Runs inside your application
              </span>
              <span>100% GO</span>
            </div>
          </div>
        </section>
        <div className="framework-rail landing-container">
          <span className="eyebrow">At home in your stack</span>
          <div>
            <span>net/http</span>
            <span>Gin</span>
            <span>Chi</span>
            <span>Fiber</span>
          </div>
          <Link href="/docs/frameworks/gin">
            Meet the adapters <ArrowUpRight size={14} />
          </Link>
        </div>

        <section
          className="modules-section landing-container"
          id="modules"
          aria-labelledby="modules-title"
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">01 / Compose your auth</p>
              <h2 id="modules-title">
                A little core.
                <br />A lot of possibilities.
              </h2>
            </div>
            <p>
              Start with the essentials. Add the pieces your product needs.
              Every module works with the same configuration, storage, and event
              system.
            </p>
          </div>
          <ModuleBuilder />
          <div className="module-footnote">
            <span>
              <span className="small-orange-dot" /> A library you import.
              Infrastructure you control.
            </span>
            <Link href="/docs/architecture">
              See how it fits together <ArrowRight size={14} />
            </Link>
          </div>
        </section>

        <section
          className="principles-section landing-container"
          aria-labelledby="principles-title"
        >
          <div className="section-heading">
            <div>
              <p className="eyebrow">02 / Made for your codebase</p>
              <h2 id="principles-title">
                Keep the control.
                <br />
                Skip the groundwork.
              </h2>
            </div>
            <Link href="/docs/architecture" className="text-link">
              Explore the architecture <ArrowUpRight size={16} />
            </Link>
          </div>
          <div className="principles-grid">
            <article>
              <span className="principle-icon">
                <LockKeyhole size={24} strokeWidth={1.5} />
              </span>
              <span className="principle-number">01</span>
              <h3>The essentials, handled.</h3>
              <p>
                Signup, login, password resets, email verification, and account
                lockout. Choose server-side sessions or stateless JWT with
                refresh token rotation.
              </p>
              <Link href="/docs/modules/core" className="text-link">
                Meet the core <ArrowUpRight size={15} />
              </Link>
            </article>
            <article>
              <span className="principle-icon">
                <Database size={24} strokeWidth={1.5} />
              </span>
              <span className="principle-number">02</span>
              <h3>Your infrastructure fits.</h3>
              <p>
                Use the built-in GORM storage, or implement an interface for
                your own database. Bring your email, SMS, logging, and event
                providers along.
              </p>
              <Link
                href="/docs/architecture#storage-architecture"
                className="text-link"
              >
                Bring your storage <ArrowUpRight size={15} />
              </Link>
            </article>
            <article>
              <span className="principle-icon">
                <Radio size={24} strokeWidth={1.5} />
              </span>
              <span className="principle-number">03</span>
              <h3>Room for your logic.</h3>
              <p>
                Hook into the moments that matter. Intercept signups, enrich
                token claims, and send notifications with ordered handlers and
                async events.
              </p>
              <Link href="/docs/enterprise" className="text-link">
                Make it your own <ArrowUpRight size={15} />
              </Link>
            </article>
          </div>
        </section>

        <section
          className="final-cta landing-container"
          aria-labelledby="cta-title"
        >
          <div>
            <p className="eyebrow">Your next import starts here</p>
            <h2 id="cta-title">
              Build something
              <br />
              worth signing in to<span>.</span>
            </h2>
          </div>
          <div className="cta-actions">
            <Link href="/docs/quickstart" className="landing-button primary">
              Open the quickstart <ArrowRight size={18} />
            </Link>
            <a href={repositoryUrl} className="text-link">
              <GitFork size={17} /> Find us on GitHub <ArrowUpRight size={15} />
            </a>
          </div>
          <ArrowDown
            className="cta-decoration"
            size={140}
            strokeWidth={0.6}
            aria-hidden
          />
        </section>
      </main>
      <footer className="landing-footer landing-container">
        <div>
          <Link href="/" className="wordmark">
            <img src="/logo.svg" alt="" width={28} height={28} />
            GoAuth<span className="wordmark-dot">.</span>
          </Link>
          <span>Made with Go. Made to be yours.</span>
        </div>
        <nav aria-label="Footer">
          <Link href="/docs">Docs</Link>
          <Link href="/docs/api/api-auth">API</Link>
          <Link href="/blog">Blog</Link>
          <a href={`${repositoryUrl}/blob/main/LICENSE`}>
            MIT License <ArrowUpRight size={12} />
          </a>
        </nav>
      </footer>
    </>
  );
}
