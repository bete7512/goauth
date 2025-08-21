import type { ReactNode } from "react";
import clsx from "clsx";
import Link from "@docusaurus/Link";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Layout from "@theme/Layout";
import HomepageFeatures from "@site/src/components/HomepageFeatures";
import Heading from "@theme/Heading";

import styles from "./index.module.css";

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx("hero hero--primary", styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/quickstart"
          >
            🚀 Get Started - 5min ⏱️
          </Link>
          <Link
            className="button button--secondary button--lg"
            to="/docs/installation"
          >
            📚 Installation Guide
          </Link>
        </div>
      </div>
    </header>
  );
}

function HomepageStats() {
  return (
    <section className={styles.stats}>
      <div className="container">
        <div className="row">
          <div className="col col--3">
            <div className="text--center">
              <div className={styles.statNumber}>8+</div>
              <div className={styles.statLabel}>OAuth Providers</div>
            </div>
          </div>
          <div className="col col--3">
            <div className="text--center">
              <div className={styles.statNumber}>6+</div>
              <div className={styles.statLabel}>Go Frameworks</div>
            </div>
          </div>
          <div className="col col--3">
            <div className="text--center">
              <div className={styles.statNumber}>100%</div>
              <div className={styles.statLabel}>Go Native</div>
            </div>
          </div>
          <div className="col col--3">
            <div className="text--center">
              <div className={styles.statNumber}>⚡</div>
              <div className={styles.statLabel}>High Performance</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function HomepageCTA() {
  return (
    <section className={styles.cta}>
      <div className="container">
        <div className="row">
          <div className="col col--8 col--offset-2">
            <div className="text--center">
              <Heading as="h2">Ready to Secure Your Go Applications?</Heading>
              <p className="hero__subtitle">
                Join thousands of developers who trust GoAuth for their
                authentication needs. Get started today with our comprehensive
                documentation and examples.
              </p>
              <div className={styles.buttons}>
                <Link
                  className="button button--primary button--lg"
                  to="/docs/quickstart"
                >
                  🚀 Start Building
                </Link>
                <Link
                  className="button button--outline button--lg"
                  to="/docs/examples/basic-auth"
                >
                  📖 View Examples
                </Link>
                <Link
                  className="button button--outline button--lg"
                  href="https://github.com/bete7512/goauth"
                >
                  ⭐ Star on GitHub
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} - Go Authentication Library`}
      description="A comprehensive, production-ready authentication library for Go applications with OAuth, JWT, and security features"
    >
      <HomepageHeader />
      <main>
        <HomepageStats />
        <HomepageFeatures />
        <HomepageCTA />
      </main>
    </Layout>
  );
}
