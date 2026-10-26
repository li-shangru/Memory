// Viewport behaviour for the graph lenses. The layout is computed on the
// server and already in the DOM; nothing here simulates anything. This file
// moves a viewBox, toggles classes, and rewrites one path attribute on drag.
(() => {
  "use strict";
  const figure = document.querySelector(".graph-figure");
  const svg = figure?.querySelector(".graph-scene");
  if (!figure || !svg) return;

  const home = svg.getAttribute("viewBox").split(" ").map(Number);
  const view = {x: home[0], y: home[1], w: home[2], h: home[3]};
  // Source names appear once the view is magnified enough to have room for
  // them. At fit scale 58 filenames collide into a smear, so the threshold is
  // the whole mechanism rather than a nicety.
  const LABEL_SCALE = 2.4;
  const applyView = () => {
    svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
    svg.classList.toggle("is-zoomed", home[2] / view.w >= LABEL_SCALE);
  };
  applyView();

  const nodes = new Map();
  for (const node of svg.querySelectorAll(".graph-node")) {
    nodes.set(node.getAttribute("data-key"), node);
  }
  const incident = new Map();
  for (const edge of svg.querySelectorAll(".graph-edge")) {
    for (const key of [edge.getAttribute("data-from"), edge.getAttribute("data-to")]) {
      const list = incident.get(key) ?? [];
      list.push(edge);
      incident.set(key, list);
    }
  }

  const centreOf = (node) => {
    const circle = node.querySelector("circle");
    if (circle) {
      return [Number(circle.getAttribute("cx")), Number(circle.getAttribute("cy"))];
    }
    const rect = node.querySelector("rect");
    return [
      Number(rect.getAttribute("x")) + Number(rect.getAttribute("width")) / 2,
      Number(rect.getAttribute("y")) + Number(rect.getAttribute("height")) / 2
    ];
  };

  const moveNode = (node, x, y) => {
    const circle = node.querySelector("circle");
    if (circle) {
      circle.setAttribute("cx", x);
      circle.setAttribute("cy", y);
    } else {
      const rect = node.querySelector("rect");
      rect.setAttribute("x", x - Number(rect.getAttribute("width")) / 2);
      rect.setAttribute("y", y - Number(rect.getAttribute("height")) / 2);
    }
    for (const edge of incident.get(node.getAttribute("data-key")) ?? []) {
      const from = nodes.get(edge.getAttribute("data-from"));
      const to = nodes.get(edge.getAttribute("data-to"));
      if (!from || !to) continue;
      const start = centreOf(from);
      const end = centreOf(to);
      edge.setAttribute("d", `M${start[0]} ${start[1]}L${end[0]} ${end[1]}`);
    }
  };

  // Hover and focus light one node with everything it touches, and dim the
  // rest. Dimming is what makes a dense region readable without labels.
  const label = document.createElement("p");
  label.className = "graph-label";
  label.hidden = true;
  figure.append(label);

  const clearFocus = () => {
    svg.classList.remove("is-focused");
    for (const element of svg.querySelectorAll(".is-active")) {
      element.classList.remove("is-active");
    }
    label.hidden = true;
  };

  const focusNode = (node) => {
    clearFocus();
    svg.classList.add("is-focused");
    node.classList.add("is-active");
    for (const edge of incident.get(node.getAttribute("data-key")) ?? []) {
      edge.classList.add("is-active");
      nodes.get(edge.getAttribute("data-from"))?.classList.add("is-active");
      nodes.get(edge.getAttribute("data-to"))?.classList.add("is-active");
    }
    label.textContent = node.querySelector("title")?.textContent ?? "";
    label.hidden = false;
  };

  svg.addEventListener("pointerover", (event) => {
    const node = event.target.closest?.(".graph-node");
    if (node) focusNode(node);
  });
  svg.addEventListener("pointerleave", clearFocus);
  svg.addEventListener("focusin", (event) => {
    const node = event.target.closest?.(".graph-node");
    if (node) focusNode(node);
  });
  svg.addEventListener("focusout", clearFocus);

  // Zoom about the pointer, bounded so the graph cannot be lost off-screen.
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = svg.getBoundingClientRect();
    const fx = (event.clientX - rect.left) / rect.width;
    const fy = (event.clientY - rect.top) / rect.height;
    const factor = event.deltaY < 0 ? 0.9 : 1 / 0.9;
    const width = Math.min(home[2] * 4, Math.max(home[2] / 12, view.w * factor));
    const height = width * (home[3] / home[2]);
    view.x += (view.w - width) * fx;
    view.y += (view.h - height) * fy;
    view.w = width;
    view.h = height;
    applyView();
  }, {passive: false});

  const toUser = (event) => {
    const rect = svg.getBoundingClientRect();
    return [
      view.x + ((event.clientX - rect.left) / rect.width) * view.w,
      view.y + ((event.clientY - rect.top) / rect.height) * view.h
    ];
  };

  // Drag moves a node if one is under the pointer, otherwise the whole view.
  //
  // Pointer capture is taken only once a drag actually starts, never on
  // pointerdown. Capturing on press retargets the synthesised click to the
  // <svg> root, and an SVG <a> that never receives the click never navigates --
  // which silently turns every node into a dead link.
  let dragging = null;
  let origin = null;
  let captured = null;
  let moved = false;
  // A drag is not a navigation, so the click the browser synthesises at the end
  // of one has to be swallowed. It cannot be swallowed on the node itself: the
  // capture taken above retargets that click to the <svg> root, so a
  // node-scoped listener never fires, stays armed, and cancels the owner's next
  // genuine click on that node -- the dead link this whole section exists to
  // avoid. The flag lives on the root, where the click lands either way, and
  // the next press clears it so a click that never arrives cannot arm it
  // forever.
  let suppressClick = false;

  svg.addEventListener(
    "click",
    (event) => {
      if (!suppressClick) return;
      suppressClick = false;
      event.preventDefault();
    },
    true
  );

  svg.addEventListener("pointerdown", (event) => {
    suppressClick = false;
    origin = toUser(event);
    dragging = event.target.closest?.(".graph-node") ?? "view";
    moved = false;
  });

  svg.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    // A press this scene never saw released -- the pointer left before the drag
    // threshold, so nothing was captured, and it came back with the button
    // already up. Hovering is not dragging.
    if (event.buttons === 0) {
      endDrag();
      return;
    }
    const [x, y] = toUser(event);
    if (!moved) {
      if (Math.abs(x - origin[0]) <= 2 && Math.abs(y - origin[1]) <= 2) return;
      moved = true;
      captured = event.pointerId;
      svg.setPointerCapture(captured);
    }
    if (dragging === "view") {
      view.x -= x - origin[0];
      view.y -= y - origin[1];
      applyView();
      return;
    }
    event.preventDefault();
    moveNode(dragging, x, y);
  });

  const endDrag = () => {
    if (captured !== null && svg.hasPointerCapture?.(captured)) {
      svg.releasePointerCapture(captured);
    }
    dragging = null;
    origin = null;
    captured = null;
    moved = false;
  };

  const finishDrag = () => {
    // Suppress only the click the browser is about to synthesise for a node
    // that actually moved, so a plain click still opens the memory. A cancelled
    // pointer synthesises no click, so it never arms the suppressor.
    if (dragging && dragging !== "view" && moved) suppressClick = true;
    endDrag();
  };

  // Bound on the window, not the scene: below the drag threshold nothing is
  // captured, so a press released anywhere else would otherwise leave the drag
  // armed for the next hover.
  window.addEventListener("pointerup", finishDrag);
  window.addEventListener("pointercancel", endDrag);
})();
