// Small behaviours the console's pages share. Loaded after htmx; the
// Content-Security-Policy allows no inline script, so they live here.
(function () {
  "use strict";

  // Press "/" to jump to the page's search box.
  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    var target = event.target;
    if (target && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
    var search = document.querySelector("[data-search]");
    if (search) {
      event.preventDefault();
      search.focus();
      search.select();
    }
  });

  // A table row marked data-href opens that page when clicked anywhere
  // outside its own links and buttons. The row's first cell holds a real
  // link, so the page still works without this script.
  document.addEventListener("click", function (event) {
    var row = event.target.closest && event.target.closest("tr[data-href]");
    if (!row || event.target.closest("a, button, input, label, td.pick")) return;
    var link = row.querySelector("a[href]");
    if (link) link.click();
  });

  // A select marked data-autosubmit submits its form when changed, so a
  // member's role can be changed in one step. The form's own button is the
  // fallback without this script.
  document.addEventListener("change", function (event) {
    var select = event.target;
    if (!select.matches || !select.matches("select[data-autosubmit]")) return;
    var form = select.closest("form");
    if (form && form.requestSubmit) form.requestSubmit();
  });

  // The users list's bulk form: the header box ticks every row on the page,
  // and a counter says how many are selected. Without this script each row
  // is ticked by hand.
  function syncBulk(form) {
    var boxes = form.querySelectorAll('input[name="ids"]');
    var ticked = form.querySelectorAll('input[name="ids"]:checked').length;
    var all = form.querySelector("[data-bulk-all]");
    if (all) {
      all.checked = boxes.length > 0 && ticked === boxes.length;
      all.indeterminate = ticked > 0 && ticked < boxes.length;
    }
    var count = form.querySelector("[data-bulk-count]");
    if (count) count.textContent = ticked ? ticked + " selected" : "";
  }
  document.addEventListener("change", function (event) {
    var form = event.target.closest && event.target.closest("form[data-bulk]");
    if (!form) return;
    if (event.target.matches("[data-bulk-all]")) {
      form.querySelectorAll('input[name="ids"]').forEach(function (box) { box.checked = event.target.checked; });
    }
    syncBulk(form);
  });

  // Passkey sign-in. The button stays hidden unless the browser supports
  // WebAuthn. Options and the assertion travel as JSON with base64url
  // binary fields, the format GoAuth's passkeys module reads.
  function fromB64url(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    var raw = atob(base64), bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes.buffer;
  }
  function toB64url(buffer) {
    var bytes = new Uint8Array(buffer), raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function passkeyError(button, message) {
    var note = button.parentNode.querySelector(".passkey-error");
    if (!note) {
      note = document.createElement("p");
      note.className = "passkey-error";
      note.setAttribute("role", "alert");
      button.parentNode.insertBefore(note, button.nextSibling);
    }
    note.textContent = message;
  }
  function postJSON(url, body) {
    return fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: body ? JSON.stringify(body) : "{}" })
      .then(function (response) { return response.json().then(function (data) { data.ok = response.ok; return data; }); });
  }
  function setupPasskeys(root) {
    if (!window.PublicKeyCredential || !navigator.credentials) return;
    root.querySelectorAll("[data-passkey-login]").forEach(function (button) {
      button.hidden = false;
    });
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest && event.target.closest("[data-passkey-login]");
    if (!button) return;
    event.preventDefault();
    button.disabled = true;
    postJSON(button.getAttribute("data-begin")).then(function (begin) {
      if (!begin.ok) throw new Error(begin.error || "Passkey sign-in could not start.");
      var options = begin.public_key;
      options.challenge = fromB64url(options.challenge);
      (options.allowCredentials || []).forEach(function (credential) { credential.id = fromB64url(credential.id); });
      return navigator.credentials.get({ publicKey: options }).then(function (credential) {
        var response = credential.response;
        return postJSON(button.getAttribute("data-finish"), {
          challenge_token: begin.challenge_token,
          credential_response: {
            id: credential.id, rawId: toB64url(credential.rawId), type: credential.type,
            response: {
              authenticatorData: toB64url(response.authenticatorData),
              clientDataJSON: toB64url(response.clientDataJSON),
              signature: toB64url(response.signature),
              userHandle: response.userHandle ? toB64url(response.userHandle) : null
            }
          }
        });
      });
    }).then(function (finish) {
      if (!finish.ok || !finish.redirect) throw new Error(finish.error || "That passkey was not accepted.");
      window.location.assign(finish.redirect);
    }).catch(function (error) {
      button.disabled = false;
      passkeyError(button, error && error.name === "NotAllowedError" ? "The passkey request was cancelled." : (error.message || "That passkey was not accepted."));
    });
  });
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { setupPasskeys(document); });
  } else {
    setupPasskeys(document);
  }
})();
