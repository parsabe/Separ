// Refmon Browser Protection: Chromium offscreen document for clipboard access.
// A service worker has no DOM and cannot touch the clipboard; this page does it on request.
"use strict";

chrome.runtime.onMessage.addListener(function (msg, sender, reply) {
  if (!msg || msg.target !== "refmon-offscreen") return false;
  var area = document.getElementById("area");
  if (msg.op === "read") {
    area.value = "";
    area.focus();
    document.execCommand("paste");
    reply({ text: area.value });
    area.value = "";
  } else if (msg.op === "write") {
    area.value = String(msg.text || "");
    area.select();
    document.execCommand("copy");
    area.value = "";
    reply({ ok: true });
  }
  return false;
});
