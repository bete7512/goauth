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
    if (!row || event.target.closest("a, button, input, label")) return;
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
})();
