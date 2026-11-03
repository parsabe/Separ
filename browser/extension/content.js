// Refmon Browser Protection: isolated-world content script (every frame).
//
// 1. Notices clipboard changes: copy and cut events (also those a page starts with
//    execCommand("copy")) and the page-world hook's signal for navigator.clipboard writes.
//    It tells the background which site it was and what the user had selected, so the background
//    can tell a user's own copy from text a page put there. Nothing is stored.
// 2. Shows the Refmon banner in the top frame when the background asks for it.
(function () {
  "use strict";
  var api = typeof browser !== "undefined" ? browser : chrome;
  var pending = null;

  function send(msg) {
    try {
      var p = api.runtime.sendMessage(msg);
      if (p && typeof p.catch === "function") p.catch(function () {});
    } catch (e) {
      /* extension reloading */
    }
  }

  function selectionText() {
    try {
      var sel = window.getSelection();
      return sel ? String(sel) : "";
    } catch (e) {
      return "";
    }
  }

  function changed() {
    var selected = selectionText();
    if (pending) clearTimeout(pending);
    // after the page's own copy handler has run and the clipboard holds the final text
    pending = setTimeout(function () {
      pending = null;
      send({
        type: "clipboard_changed",
        domain: location.hostname || "",
        selection: selected.slice(0, 20000),
      });
    }, 120);
  }

  document.addEventListener("copy", changed, true);
  document.addEventListener("cut", changed, true);
  document.addEventListener("refmon:clipboard-write", changed, true);

  // -- top frame only: the page address (checked only when the admin enabled it) and the banner --
  if (window.top !== window) return;

  send({ type: "navigated", url: location.href, domain: location.hostname || "" });

  var host = null;

  function removeBanner() {
    if (host && host.parentNode) host.parentNode.removeChild(host);
    host = null;
  }

  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  }

  function showBanner(msg) {
    removeBanner();
    host = document.createElement("div");
    host.style.cssText = "all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;";
    var root = host.attachShadow({ mode: "closed" });
    var style = el("style");
    style.textContent =
      ".b{font:14px/1.45 system-ui,sans-serif;background:#7a1010;color:#fff;padding:12px 16px;" +
      "display:flex;gap:12px;align-items:flex-start;box-shadow:0 2px 10px rgba(0,0,0,.35)}" +
      ".b.warn{background:#7a5410}.t{font-weight:600;margin-bottom:2px}.x{flex:1}" +
      "button{font:inherit;border:1px solid #fff;background:transparent;color:#fff;" +
      "border-radius:6px;padding:4px 10px;cursor:pointer;white-space:nowrap}" +
      "button.p{background:#fff;color:#7a1010}";
    var box = el("div", null, msg.level === "warn" ? "b warn" : "b");
    var text = el("div", null, "x");
    text.appendChild(el("div", "Refmon: " + msg.title, "t"));
    text.appendChild(el("div", msg.body));
    if (msg.advice) text.appendChild(el("div", msg.advice));
    box.appendChild(text);
    if (msg.hold_id) {
      var keep = el("button", "Keep it, I trust this");
      var drop = el("button", "Remove it", "p");
      keep.onclick = function () {
        send({ type: "hold_answer", hold_id: msg.hold_id, answer: "continue" });
        removeBanner();
      };
      drop.onclick = function () {
        send({ type: "hold_answer", hold_id: msg.hold_id, answer: "stop" });
        removeBanner();
      };
      if (msg.can_continue) box.appendChild(keep);
      box.appendChild(drop);
    } else {
      var close = el("button", "Close");
      close.onclick = removeBanner;
      box.appendChild(close);
    }
    root.appendChild(style);
    root.appendChild(box);
    (document.documentElement || document).appendChild(host);
  }

  api.runtime.onMessage.addListener(function (msg) {
    if (msg && msg.type === "refmon_banner") showBanner(msg);
    if (msg && msg.type === "refmon_banner_clear") removeBanner();
  });
})();
