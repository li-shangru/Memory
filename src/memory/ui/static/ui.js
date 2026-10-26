(() => {
  "use strict";
  // Opaque identifiers may distinguish CRLF from LF. Restore their exact
  // values after HTML parsing, without adding unsuccessful checkboxes or
  // option elements to a form's submitted entries.
  for (const reference of document.querySelectorAll("[data-exact-reference]")) {
    reference.value = JSON.parse(reference.dataset.exactReference);
  }
  // HTML controls normalize line endings. Keep an unchanged displayed value
  // bound to its exact server-rendered bytes so editing wording cannot alter
  // a tag or turn an existing evidence excerpt into a different locator.
  const exactValues = new Map();
  for (const control of document.querySelectorAll("[data-exact-value]")) {
    const original = JSON.parse(control.dataset.exactValue);
    control.value = original;
    exactValues.set(control, {original, displayed: control.value});
  }
  const unsavedForms = new Set();
  for (const form of document.querySelectorAll("form[data-unsaved-warning]")) {
    form.addEventListener("input", () => { unsavedForms.add(form); });
  }
  const orderedPrefixes = ["tag.", "evidence."];
  const orderedIndex = (name) => {
    for (const prefix of orderedPrefixes) {
      if (!name.startsWith(prefix)) continue;
      const rest = name.slice(prefix.length);
      const separator = rest.indexOf(".");
      const raw = separator === -1 ? rest : rest.slice(0, separator);
      const field = separator === -1 ? "" : rest.slice(separator + 1);
      if (!/^\d+$/.test(raw)) return null;
      return {prefix: prefix, index: Number(raw), field: field};
    }
    return null;
  };
  // The owner form always renders every optional ordered slot. Submit only the
  // slots the owner filled, renumbered contiguously, and never an empty one.
  const orderedBody = (form) => {
    const body = new URLSearchParams();
    const slots = new Map();
    const fields = new FormData(form);
    for (const control of form.querySelectorAll("[data-exact-value]")) {
      const exact = exactValues.get(control);
      if (exact && control.value === exact.displayed) {
        fields.set(control.name, exact.original);
      }
    }
    for (const [name, value] of fields) {
      const parsed = orderedIndex(name);
      if (parsed === null) {
        body.append(name, value);
        continue;
      }
      const key = `${parsed.prefix}${parsed.index}`;
      const slot = slots.get(key) ?? {prefix: parsed.prefix, fields: []};
      slot.fields.push([parsed.field, value]);
      slots.set(key, slot);
    }
    const counters = new Map();
    for (const slot of slots.values()) {
      if (slot.fields.every(([, value]) => value === "")) continue;
      const next = counters.get(slot.prefix) ?? 0;
      counters.set(slot.prefix, next + 1);
      for (const [field, value] of slot.fields) {
        if (value === "") continue;
        const name = field ? `${slot.prefix}${next}.${field}` : `${slot.prefix}${next}`;
        body.append(name, value);
      }
    }
    return body;
  };
  // Selection is a read of another immutable proposal, never a change to the
  // target of the values already loaded. The GET form carries only item_id
  // and drops any retained refusal handle from the previous item.
  for (const selector of document.querySelectorAll("form[data-review-item-selector]")) {
    const item = selector.querySelector("select[name=item_id]");
    if (!item) continue;
    const loadedItem = item.value;
    item.addEventListener("change", () => {
      if (item.value !== loadedItem) selector.requestSubmit();
    });
    selector.addEventListener("submit", (event) => {
      event.preventDefault();
      const destination = new URL(selector.action);
      destination.search = new URLSearchParams({item_id: item.value}).toString();
      // If the unsaved-change prompt is cancelled, the selector still names
      // the proposal held by the edit form beside it.
      item.value = loadedItem;
      window.location.assign(destination);
    });
  }
  const csrf = document.querySelector("meta[name=memory-csrf]")?.content;
  const submitting = new Set();
  const reportSubmissionFailure = (form) => {
    let notice = form.querySelector("[data-submission-error]");
    if (!notice) {
      notice = document.createElement("p");
      notice.setAttribute("data-submission-error", "");
      notice.setAttribute("role", "alert");
      notice.className = "notice";
      notice.tabIndex = -1;
      form.append(notice);
    }
    // A lost response may follow a committed write. Preserve the form without
    // claiming nothing changed or automatically repeating the submission.
    notice.textContent = "Request unavailable. Your entries remain on this page. " +
      "Check whether the request completed before submitting again.";
    notice.hidden = false;
    notice.focus();
  };
  for (const form of document.querySelectorAll(
    "form[data-authenticated-post], form[data-authenticated-upload]"
  )) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (submitting.has(form)) return;
      if (!csrf) {
        reportSubmissionFailure(form);
        return;
      }
      const controls = Array.from(form.querySelectorAll(
        "input:enabled, textarea:enabled, select:enabled, button:enabled"
      ));
      const notice = form.querySelector("[data-submission-error]");
      if (notice) notice.hidden = true;
      submitting.add(form);
      try {
        const upload = form.hasAttribute("data-authenticated-upload");
        const body = upload ? new FormData(form) : form.hasAttribute("data-ordered-fields")
          ? orderedBody(form) : new URLSearchParams(new FormData(form));
        // Freeze the submitted values so a successful redirect cannot discard
        // edits made after this request's body was captured.
        for (const control of controls) control.disabled = true;
        const response = await window.fetch(form.action, {
          method: "POST",
          body: body,
          credentials: "same-origin",
          headers: upload ? {"X-Memory-CSRF": csrf} : {
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "X-Memory-CSRF": csrf
          }
        });
        if (!response.ok || !response.redirected) {
          throw new Error("submission unavailable");
        }
        unsavedForms.delete(form);
        window.location.assign(response.url);
      } catch {
        submitting.delete(form);
        for (const control of controls) control.disabled = false;
        reportSubmissionFailure(form);
      }
    });
  }
  for (const dropZone of document.querySelectorAll("form[data-drop-zone]")) {
    const input = dropZone.querySelector('input[type="file"]');
    if (!input) continue;
    dropZone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
    dropZone.addEventListener("dragleave", (event) => {
      if (!dropZone.contains(event.relatedTarget)) {
        dropZone.classList.remove("is-dragging");
      }
    });
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
      if (!input.disabled && event.dataTransfer?.files.length) {
        input.files = event.dataTransfer.files;
      }
    });
  }
  window.addEventListener("beforeunload", (event) => {
    if (unsavedForms.size === 0) return;
    event.preventDefault();
    event.returnValue = "";
  });
  // Copy-to-clipboard for the disclosed identifiers and digests. The owner
  // hears one confirmation from a single shared live region; nothing else on
  // the page changes, and no request leaves the process.
  const announce = document.querySelector(".copy-announce");
  let announceTimer = null;
  // Copying twice must be heard twice. A live region only announces a change,
  // so the identical second message is cleared first and set on the next frame.
  const reportCopy = (message) => {
    if (!announce) return;
    if (announceTimer !== null) window.clearTimeout(announceTimer);
    announce.textContent = "";
    window.requestAnimationFrame(() => {
      announce.textContent = message;
      announceTimer = window.setTimeout(() => {
        announce.textContent = "";
        announceTimer = null;
      }, 2000);
    });
  };
  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("button[data-copy-value]");
    if (!button) return;
    const value = button.getAttribute("data-copy-value") ?? "";
    const clipboard = window.navigator.clipboard;
    if (!clipboard) {
      reportCopy("Copy failed");
      return;
    }
    clipboard.writeText(value).then(
      () => reportCopy("Copied"),
      () => reportCopy("Copy failed")
    );
  });
})();
