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
        <p className="hero__subtitle">
          A modular, pluggable authentication library for Go.
          <br />
          Import it. Configure it. Ship it.
        </p>
        <p className={styles.heroDescription}>
          GoAuth is not a separate auth server you deploy and maintain.
          It is a Go package you import into your existing application.
          Pick the modules you need, bring your own storage and infrastructure,
          and get production-ready auth in minutes.
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/quickstart"
          >
            Get Started
          </Link>
          <Link
            className="button button--secondary button--lg"
            to="/docs/installation"
          >
            Installation
          </Link>
          <Link
            className="button button--outline button--lg"
            href="https://github.com/bete7512/goauth"
          >
            GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

function HomepageStats() {
  const stats = [
    { value: "12", label: "Modules" },
    { value: "4", label: "Frameworks" },
    { value: "4", label: "OAuth Providers" },
    { value: "100%", label: "Go" },
  ];

  return (
    <section className={styles.stats}>
      <div className="container">
        <div className="row">
          {stats.map((stat, idx) => (
            <div className="col col--3" key={idx}>
              <div className="text--center">
                <div className={styles.statNumber}>{stat.value}</div>
                <div className={styles.statLabel}>{stat.label}</div>
              </div>
            </div>
          ))}
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
              <Heading as="h2">Add Auth to Your Go App Today</Heading>
              <p className="hero__subtitle">
                Three lines to initialize. Twelve modules to choose from.
                Every integration point is an interface you can swap.
              </p>
              <div className={styles.buttons}>
                <Link
                  className="button button--primary button--lg"
                  to="/docs/quickstart"
                >
                  Read the Quickstart
                </Link>
                <Link
                  className="button button--outline button--lg"
                  to="/docs/showcase"
                >
                  View Examples
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
      title={`${siteConfig.title} - Modular Authentication Library for Go`}
      description="A modular, pluggable authentication library for Go. Drop-in auth with 12 composable modules, pluggable storage, event-driven hooks, and framework adapters for Gin, Chi, Fiber, and net/http."
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
