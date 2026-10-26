(() => {
  "use strict";
  const capability = window.location.hash.slice(1);
  window.history.replaceState(null, "", window.location.pathname);
  if (!capability) {
    document.body.textContent = "This launch link is unavailable.";
    return;
  }
  window.fetch("/session", {
    method: "POST",
    body: capability,
    credentials: "same-origin",
    headers: {"Content-Type": "text/plain"}
  }).then((response) => {
    if (!response.ok) {
      document.body.textContent = "This launch link is unavailable.";
      return;
    }
    window.location.replace(response.url);
  }).catch(() => {
    document.body.textContent = "This launch link is unavailable.";
  });
})();
