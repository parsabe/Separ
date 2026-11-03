// Refmon Browser Protection: page-world hook (runs before page scripts, in every frame).
//
// It only says "a page script wrote to the clipboard". It never reads or forwards the text: the
// extension re-reads the real clipboard itself, so a page that forges this signal can at most make
// Refmon look at what is already on the clipboard. A page that copies through a copy event or
// document.execCommand("copy") is seen by content.js without this hook.
(function () {
  "use strict";
  var SIGNAL = "refmon:clipboard-write";
  function signal() {
    try {
      document.dispatchEvent(new CustomEvent(SIGNAL));
    } catch (e) {
      /* never break the page */
    }
  }
  function wrap(obj, name) {
    if (!obj || typeof obj[name] !== "function") return;
    var original = obj[name];
    obj[name] = function () {
      var result = original.apply(this, arguments);
      Promise.resolve(result).then(signal, function () {});
      return result;
    };
  }
  if (typeof Clipboard !== "undefined" && Clipboard.prototype) {
    wrap(Clipboard.prototype, "writeText");
    wrap(Clipboard.prototype, "write");
  }
})();
