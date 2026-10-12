// Check documentation against this checkout rather than a published Go module.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const read = (path) => readFileSync(join(root, path), "utf8");
function go(args) {
  try {
    return execFileSync("go", args, {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120000,
    });
  } catch (error) {
    process.stderr.write((error.stdout ?? "").slice(-3000));
    process.stderr.write((error.stderr ?? "").slice(-3000));
    throw new Error(`Go documentation check failed (${args[0]}); see compiler/runtime output above.`);
  }
}
const blocks = (source) =>
  [...source.matchAll(/^```go\r?\n([\s\S]*?)^```/gm)].map((m) => m[1]);
const dir = mkdtempSync(join(tmpdir(), "goauth-doc-examples-"));
try {
  const quickstart = blocks(read("docs/docs/quickstart.md")).find((s) =>
    s.startsWith("package main"),
  );
  assert.ok(quickstart, "quickstart needs a complete Go program");
  const main = join(dir, "main.go");
  writeFileSync(main, quickstart);
  go(["test", main]);
  const paths = [
    "docs/docs/showcase.md",
    "docs/docs/api/auth.md",
    "docs/docs/quickstart.md",
    ...readdirSync(join(root, "docs/docs/modules"))
      .filter((p) => p.endsWith(".md"))
      .map((p) => `docs/docs/modules/${p}`),
  ];
  const snippets = paths.flatMap((path) =>
    blocks(read(path))
      .filter(
        (source) =>
          source.includes("a.Use(") && !source.startsWith("package main"),
      )
      .map((source) => ({
        path,
        source: source.replace(/^import (?:\([\s\S]*?^\)|"[^\n]+")\s*/gm, ""),
      })),
  );
  const aliases = {
    auth: "pkg/auth",
    config: "pkg/config",
    types: "pkg/types",
    models: "pkg/models",
    session: "pkg/modules/session",
    stateless: "pkg/modules/stateless",
    magiclink: "pkg/modules/magiclink",
    notification: "pkg/modules/notification",
    senders: "pkg/modules/notification/senders",
    twofactor: "pkg/modules/twofactor",
    oauth: "pkg/modules/oauth",
    captcha: "pkg/modules/captcha",
    csrf: "pkg/modules/csrf",
    passkeys: "pkg/modules/passkeys",
    admin: "pkg/modules/admin",
    audit: "pkg/modules/audit",
    invitation: "pkg/modules/invitation",
    organization: "pkg/modules/organization",
  };
  const supplied = {
    ctx: "context.Context",
    mySessionStore: "types.SessionStorage",
    myCoreStore: "types.CoreStorage",
    customUserRepo: "models.UserRepository",
    myCustomUserRepo: "models.UserRepository",
    customAuditRepo: "models.AuditLogRepository",
    myCustomAuditRepo: "models.AuditLogRepository",
    myEmailSender: "notification.EmailSender",
    myCustomEmailSender: "notification.EmailSender",
    emailSender: "notification.EmailSender",
    myCustomSMSSender: "notification.SMSSender",
  };
  const files = [];
  for (const [
    index,
    { path: sourcePath, source: snippet },
  ] of snippets.entries()) {
    const parameters = [
      "a *auth.Auth",
      ...Object.entries(supplied)
        .filter(([name]) => new RegExp(`\\b${name}\\b`).test(snippet))
        .map(([name, type]) => `${name} ${type}`),
    ].join(", ");
    const body = `${parameters}\n${snippet}`.replace(
      /"(?:\\.|[^"\\])*"|`[^`]*`|\/\/[^\n]*/g,
      "",
    );
    const imports = Object.entries(aliases)
      .filter(([alias]) => new RegExp(`\\b${alias}\\.`).test(body))
      .map(([, path]) => `"github.com/bete7512/goauth/${path}"`);
    for (const name of ["time", "os", "context", "http"]) {
      if (new RegExp(`\\b${name}\\.`).test(body))
        imports.push(`"${name === "http" ? "net/http" : name}"`);
    }
    const path = join(dir, `snippet${index}.go`);
    writeFileSync(
      path,
      `// ${sourcePath}\npackage examples\nimport (${imports.join("\n")})\nfunc example${index}(${parameters}) error {\n${snippet}\nreturn nil\n}\n`,
    );
    files.push(path);
  }
  go(["test", ...files]);
  console.log(
    `Compiled quickstart and ${snippets.length} registration examples against this checkout.`,
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const declarationPattern = /^type (\w+) (?:struct|interface) \{[\s\S]*?^\}/gm;
const declarations = new Map();
for (const folder of ["pkg/models", "pkg/types"]) {
  for (const file of readdirSync(join(root, folder)).filter(
    (p) => p.endsWith(".go") && !p.endsWith("_test.go"),
  )) {
    for (const match of read(`${folder}/${file}`).matchAll(declarationPattern))
      declarations.set(match[1], match[0]);
  }
}
let matched = 0;
for (const match of read("docs/docs/api/models.md").matchAll(
  declarationPattern,
)) {
  assert.equal(
    match[0],
    declarations.get(match[1]),
    `Model reference drift: ${match[1]}`,
  );
  matched++;
}
console.log(
  `Verified ${matched} model and interface declarations against source.`,
);
const output = go(["run", "docs/scripts/check-api.go"]);
const json = output
  .split("\n")
  .find((line) => line.startsWith("DOCS_API_JSON="));
assert.ok(json, "runtime fixture did not produce route inventory");
const routes = JSON.parse(json.slice("DOCS_API_JSON=".length));
const doc = read("docs/docs/api/endpoints.md")
  .replaceAll("&#123;", "{")
  .replaceAll("&#125;", "}");
const documented = new Set(
  [...doc.matchAll(/<summary><code>(\w+)<\/code> <code>([^<]+)<\/code>/g)].map(
    (m) => `${m[1]} ${m[2].split("?")[0]}`,
  ),
);
const runtime = new Set(routes.map((r) => `${r.Method} ${r.Path}`));
for (const route of runtime)
  assert.ok(documented.has(route), `Missing endpoint documentation: ${route}`);
for (const route of documented)
  assert.ok(
    runtime.has(route),
    `Documented endpoint is not registered: ${route}`,
  );
console.log(
  `Verified ${runtime.size} endpoint method/path pairs and signup/login/refresh/replay/logout flows in both strategies.`,
);
