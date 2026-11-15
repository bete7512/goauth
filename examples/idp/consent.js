// The consent page of the example. It does what a host's frontend does for
// the identity provider: make sure the user is signed in, show what the
// application asks for, and report the decision.
(() => {
  const requestId = new URLSearchParams(location.search).get("request_id");
  const sections = ["loading", "signin", "consent", "done"];
  const $ = (id) => document.getElementById(id);
  const tokenKey = "goauth-example-token";
  let signingUp = false;

  const show = (name) => {
    for (const id of sections) $(id).hidden = id !== name;
  };
  const fail = (message) => {
    $("error").textContent = message;
    $("error").hidden = !message;
  };
  const finish = (message) => {
    $("done-message").textContent = message;
    show("done");
  };

  // The user's GoAuth access token lives in this tab only.
  const token = () => sessionStorage.getItem(tokenKey);

  async function call(path, method = "GET", body) {
    const headers = {};
    if (token()) headers.Authorization = `Bearer ${token()}`;
    if (body) headers["Content-Type"] = "application/json";
    const response = await fetch(`/auth${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const payload = await response.json().catch(() => ({}));
    return { status: response.status, data: payload.data || {} };
  }

  function askToSignIn(note) {
    sessionStorage.removeItem(tokenKey);
    $("signin-note").textContent = note || "Sign in to continue to the application.";
    show("signin");
  }

  async function load() {
    fail("");
    if (!requestId) return finish("This page is opened by an application that wants to sign you in.");
    if (!token()) return askToSignIn();

    const { status, data } = await call(`/oidc/consent/${encodeURIComponent(requestId)}`);
    if (status === 401) return askToSignIn();
    if (status === 404) return finish("This sign-in request has expired. Go back to the application and try again.");
    if (status !== 200) return finish(data.message || "Something went wrong.");

    // The application asked for a fresh sign-in (prompt=login or max_age).
    if (data.login_required) return askToSignIn(`${data.client.name} asks you to sign in again.`);
    // Nothing to ask: already approved, or an application of the host's own.
    if (!data.consent_required) return decide("approve");

    $("client-name").textContent = data.client.name;
    $("redirect-host").textContent = data.redirect_host;
    $("scopes").replaceChildren(...data.scopes.map((scope) => {
      const item = document.createElement("li");
      item.textContent = scope.description || scope.name;
      return item;
    }));
    show("consent");
  }

  async function decide(decision) {
    show("loading");
    const { status, data } = await call(`/oidc/consent/${encodeURIComponent(requestId)}/${decision}`, "POST");
    if (status === 200 && data.redirect_to) {
      location.replace(data.redirect_to);
      return;
    }
    if (status === 401 && data.code === "IDP_LOGIN_REQUIRED") return askToSignIn("The application asks you to sign in again.");
    if (status === 401) return askToSignIn();
    finish(data.message || "This sign-in request can no longer be completed.");
  }

  $("toggle-signup").addEventListener("click", () => {
    signingUp = !signingUp;
    $("name-field").hidden = !signingUp;
    $("signin-title").textContent = signingUp ? "Create an account" : "Sign in";
    $("signin-submit").textContent = signingUp ? "Create account" : "Sign in";
    $("toggle-signup").textContent = signingUp ? "Sign in instead" : "Create an account instead";
    $("password").autocomplete = signingUp ? "new-password" : "current-password";
  });

  $("signin-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    fail("");
    const credentials = { email: $("email").value.trim(), password: $("password").value };
    if (signingUp) {
      const created = await call("/signup", "POST", { ...credentials, name: $("name").value.trim() || credentials.email });
      if (created.status !== 201) return fail(created.data.message || "The account could not be created.");
    }
    const { status, data } = await call("/login", "POST", credentials);
    if (status !== 200 || !data.access_token) return fail(data.message || "Wrong email or password.");
    sessionStorage.setItem(tokenKey, data.access_token);
    $("password").value = "";
    show("loading");
    load();
  });

  $("approve").addEventListener("click", () => decide("approve"));
  $("deny").addEventListener("click", () => decide("deny"));

  load().catch(() => finish("Something went wrong."));
})();
