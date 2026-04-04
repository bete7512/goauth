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
    title: "Drop-in Authentication",
    Svg: require("@site/static/img/undraw_docusaurus_mountain.svg").default,
    description: (
      <>
        Add signup, login, password reset, email verification, and session
        management to any Go app with a few lines of code. GoAuth is a library
        you import — not a separate service to deploy.
      </>
    ),
  },
  {
    title: "Plug In Your Own Infrastructure",
    Svg: require("@site/static/img/undraw_docusaurus_tree.svg").default,
    description: (
      <>
        GoAuth uses interfaces for everything: storage, event backends, email/SMS
        delivery, and logging. Use the built-in GORM storage and worker pool, or
        implement the interface to bring Kafka, NATS, Redis, MongoDB, SendGrid,
        Twilio, or any custom provider.
      </>
    ),
  },
  {
    title: "Session or Stateless — Your Choice",
    Svg: require("@site/static/img/undraw_docusaurus_react.svg").default,
    description: (
      <>
        Choose server-side sessions with optional cookie-cache for fast
        validation, or stateless JWT with nonce-based refresh token rotation.
        Both support 2FA challenges, org-scoped claims, and account lockout.
      </>
    ),
  },
  {
    title: "OAuth with PKCE",
    Svg: require("@site/static/img/undraw_docusaurus_mountain.svg").default,
    description: (
      <>
        Built-in Google, GitHub, Microsoft, and Discord providers with automatic
        PKCE. Users sign in via OAuth and GoAuth handles account creation,
        linking, and token issuance.
      </>
    ),
  },
  {
    title: "Multi-Organization Support",
    Svg: require("@site/static/img/undraw_docusaurus_tree.svg").default,
    description: (
      <>
        Built-in organization module with roles (owner, admin, member),
        invitations with expiry, org-scoped JWT claims, and org switching.
        Build SaaS products without writing org management from scratch.
      </>
    ),
  },
  {
    title: "Event-Driven Hooks",
    Svg: require("@site/static/img/undraw_docusaurus_react.svg").default,
    description: (
      <>
        Subscribe to before/after events on any operation. Multiple handlers per
        event with priority ordering, async processing via worker pool, retry
        policies, and dead letter queue. Intercept signups, enrich JWT claims,
        send notifications — all through events.
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
