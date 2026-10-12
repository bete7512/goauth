"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowUpRight, Check, LockKeyhole, Plus } from "lucide-react";
import { CopyButton } from "./copy-button";

const modules = [
  {
    id: "passkeys",
    title: "Passkeys",
    note: "WebAuthn sign-in",
    call: "passkeys.New(passkeyConfig)",
  },
  {
    id: "twofactor",
    title: "Two-factor",
    note: "TOTP + backup codes",
    call: "twofactor.New()",
  },
  {
    id: "oauth",
    title: "OAuth",
    note: "Google, GitHub & more",
    call: "oauth.New(oauthConfig)",
  },
  {
    id: "organization",
    title: "Organizations",
    note: "Roles + invitations",
    call: "organization.New(nil)",
  },
  {
    id: "audit",
    title: "Audit logs",
    note: "Security event history",
    call: "admin.New(nil),\n    audit.New(nil)",
  },
] as const;

type ModuleId = (typeof modules)[number]["id"];

export function ModuleBuilder() {
  const [strategy, setStrategy] = useState("stateless");
  const [enabled, setEnabled] = useState<ModuleId[]>(["twofactor", "oauth"]);
  const code = `// 01. Create your instance\na, err := auth.New(cfg)\nif err != nil {\n    log.Fatal(err)\n}\n\n// 02. Register your modules\nfor _, module := range []config.Component{\n    ${strategy}.New(nil),\n${modules
    .filter((module) => enabled.includes(module.id))
    .map((module) => `    ${module.call},`)
    .join(
      "\n",
    )}${enabled.length ? "\n" : ""}} {\n    if err := a.Use(module); err != nil {\n        log.Fatal(err)\n    }\n}\n\n// 03. Ready your application\nif err := a.Initialize(ctx); err != nil {\n    log.Fatal(err)\n}\ndefer a.Close()`;
  function toggle(id: ModuleId) {
    setEnabled((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id],
    );
  }
  return (
    <div className="module-workbench">
      <div className="module-controls">
        <div className="core-module">
          <LockKeyhole size={18} />
          <span>
            Core authentication
            <small>Signup, profiles, passwords, verification</small>
          </span>
          <span className="included-label">Included</span>
        </div>
        <fieldset className="auth-strategy">
          <legend>
            <span>01</span> Choose your auth strategy
          </legend>
          <div className="strategy-options">
            {[
              { id: "stateless", label: "Stateless JWT" },
              { id: "session", label: "Sessions" },
            ].map((option) => (
              <label
                key={option.id}
                className={strategy === option.id ? "selected" : ""}
              >
                <input
                  type="radio"
                  name="auth-strategy"
                  value={option.id}
                  checked={strategy === option.id}
                  onChange={() => setStrategy(option.id)}
                />
                {option.label}
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset className="optional-modules">
          <legend>
            <span>02</span> Add what your app needs
          </legend>
          {modules.map((module) => (
            <label
              key={module.id}
              className={`module-option ${enabled.includes(module.id) ? "selected" : ""}`}
            >
              <input
                type="checkbox"
                checked={enabled.includes(module.id)}
                onChange={() => toggle(module.id)}
              />
              <span className="module-check" aria-hidden>
                {enabled.includes(module.id) ? (
                  <Check size={15} />
                ) : (
                  <Plus size={15} />
                )}
              </span>
              <span>
                {module.title}
                <small>{module.note}</small>
              </span>
            </label>
          ))}
        </fieldset>
        <Link
          href="/docs/architecture#module-dependency-graph"
          className="text-link"
        >
          Explore all modules <ArrowUpRight size={16} />
        </Link>
      </div>
      <div className="builder-code">
        <div className="code-toolbar">
          <span>
            <span className="code-dot" /> main.go
          </span>
          <span className="code-toolbar-end">
            <span className="snippet-label">Configuration excerpt</span>
            <CopyButton value={code} />
          </span>
        </div>
        <pre tabIndex={0} aria-label="Go configuration example">
          <code>
            {code.split("\n").map((line, index) => (
              <span className="code-line" key={index}>
                <span className="line-number" aria-hidden>
                  {index + 1}
                </span>
                <span
                  className={
                    line.trim().startsWith("//") ? "syntax-comment" : ""
                  }
                >
                  {line
                    .split(
                      /(\b(?:if|for|range|defer|nil)\b|\b(?:New|Use|Initialize|Close|Fatal)\b)/g,
                    )
                    .map((token, i) => (
                      <span
                        key={i}
                        className={
                          /^(if|for|range|defer|nil)$/.test(token)
                            ? "syntax-keyword"
                            : /^(New|Use|Initialize|Close|Fatal)$/.test(token)
                              ? "syntax-function"
                              : undefined
                        }
                      >
                        {token}
                      </span>
                    ))}
                </span>
                {"\n"}
              </span>
            ))}
          </code>
        </pre>
        <div className="builder-note">
          <span>Use your app, provider, and relying-party configuration.</span>
          <Link href="/docs/quickstart">
            Full setup & imports <ArrowUpRight size={13} />
          </Link>
        </div>
        <span className="sr-only" role="status">
          {strategy === "session" ? "Sessions" : "Stateless JWT"} with{" "}
          {enabled.length} optional modules selected. Code example updated.
        </span>
      </div>
    </div>
  );
}
