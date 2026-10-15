// Every link that leaves the site (a specification, a case file on GitHub, a CI run) opens in one
// reused window named "spec", so a reader keeps their place here and does not collect a new tab
// per click. A link counts as leaving when it goes to another origin, or to a path on this origin
// outside the site's own root. Daniel asked for the name "spec" on 2026-10-15.
(function () {
  var root = new URL(".", document.querySelector("script[src*='external-links.js']").src);
  root = new URL("..", root);
  function mark() {
    document.querySelectorAll("a[href]").forEach(function (a) {
      var url;
      try {
        url = new URL(a.getAttribute("href"), document.baseURI);
      } catch (e) {
        return;
      }
      if (!/^https?:$/.test(url.protocol)) return;
      var inside = url.origin === root.origin && url.pathname.indexOf(root.pathname) === 0;
      if (!inside) {
        a.target = "spec";
        a.rel = "noopener";
      }
    });
  }
  if (typeof document$ !== "undefined" && document$.subscribe) {
    document$.subscribe(mark);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mark);
  } else {
    mark();
  }
})();
