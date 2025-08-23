import type { ReactNode } from "react";
import clsx from "clsx";
import Heading from "@theme/Heading";
import styles from "./styles.module.css";

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<"svg">>;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: "Multiple Authentication Methods",
    Svg: require("@site/static/img/undraw_docusaurus_mountain.svg").default,
    description: (
      <>
        Support for OAuth 2.0, JWT, Magic Links, and Two-Factor Authentication.
        Choose the method that best fits your application's security
        requirements.
      </>
    ),
  },
  {
    title: "Framework Integration",
    Svg: require("@site/static/img/undraw_docusaurus_tree.svg").default,
    description: (
      <>
        Native support for popular Go web frameworks including Gin, Echo, Fiber,
        Chi, Gorilla Mux, and Iris. Easy integration with your existing
        codebase.
      </>
    ),
  },
  {
    title: "Enterprise Security",
    Svg: require("@site/static/img/undraw_docusaurus_react.svg").default,
    description: (
      <>
        Built-in rate limiting, CSRF protection, reCAPTCHA integration, and
        comprehensive security features. Production-ready from day one.
      </>
    ),
  },
  {
    title: "OAuth Providers",
    Svg: require("@site/static/img/undraw_docusaurus_mountain.svg").default,
    description: (
      <>
        Pre-built integrations with Google, GitHub, Facebook, Microsoft, Apple,
        Discord, LinkedIn, and Twitter. Easy social login implementation.
      </>
    ),
  },
  {
    title: "Flexible Storage",
    Svg: require("@site/static/img/undraw_docusaurus_tree.svg").default,
    description: (
      <>
        Support for PostgreSQL, MySQL, SQLite, and custom storage backends.
        Redis integration for caching and session management.
      </>
    ),
  },
  {
    title: "Developer Experience",
    Svg: require("@site/static/img/undraw_docusaurus_react.svg").default,
    description: (
      <>
        Comprehensive documentation, examples, and testing utilities. Built with
        Go developers in mind for maximum productivity.
      </>
    ),
  },
];

function Feature({ title, Svg, description }: FeatureItem) {
  return (
    <div className={clsx("col col--4")}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
