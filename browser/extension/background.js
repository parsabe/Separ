// Refmon Browser Protection: background (Firefox event page / Chromium service worker).
//
// Reads the clipboard after a page changed it, asks the local Refmon program (through the
// native-messaging host org.refmon.browser) what the text would do if pasted into a shell, and
// acts on the answer: replace the clipboard with a harmless warning (block), hold it until the
// user answers (hold), only warn (warn mode), or leave it (allow). Downloads are checked the same
// way. The user is never locked out of anything: only the one dangerous action is stopped.
//
// Privacy: clipboard text and addresses are held in memory only for as long as a decision or a
// hold needs them, are sent to nothing but the local host, and are never stored or logged.
"use strict";

var api = typeof browser !== "undefined" ? browser : chrome;
var IS_FIREFOX = typeof browser !== "undefined";
var HOST = "org.refmon.browser";
var WARNING =
  "Refmon removed a command that a web page put on your clipboard. " +
  "No real website asks you to paste commands into a terminal or the Run dialog.";
var HELD = "Refmon is holding a command that a web page put on your clipboard. Answer the Refmon banner first.";
var UNAVAILABLE = { decision: "unavailable", reason: "host_missing", action: "none" };
var DOMAIN_RE = /^[a-z0-9.-]{1,253}$/;

var settings = { checkNavigation: false, checkDownloads: true };
var port = null;
var nextId = 1;
var waiting = {};
var lastText = null;
var holds = {}; // hold_id -> { what, text, downloadId, tabId, timer }

function quiet(p) {
  // a promise-returning API call whose failure (a tab without a listener) is not an error
  if (p && typeof p.catch === "function") p.catch(function () {});
}

async function loadSettings() {
  try {
    var items = await api.storage.managed.get(null);
    if (!items) return;
    if (typeof items.checkNavigation === "boolean") settings.checkNavigation = items.checkNavigation;
    if (typeof items.checkDownloads === "boolean") settings.checkDownloads = items.checkDownloads;
  } catch (e) {
    /* no managed storage configured: defaults */
  }
}

// -- native messaging ---------------------------------------------------------------------------

function connect() {
  port = api.runtime.connectNative(HOST);
  port.onMessage.addListener(function (msg) {
    var done = msg && waiting[msg.id];
    if (done) {
      delete waiting[msg.id];
      done(msg);
    }
  });
  port.onDisconnect.addListener(function () {
    port = null;
    var pendingCalls = waiting;
    waiting = {};
    Object.keys(pendingCalls).forEach(function (k) {
      pendingCalls[k](Object.assign({}, UNAVAILABLE));
    });
  });
}

function ask(message) {
  return new Promise(function (resolve) {
    try {
      if (!port) connect();
    } catch (e) {
      resolve(Object.assign({}, UNAVAILABLE));
      return;
    }
    var id = nextId++;
    message.id = id;
    waiting[id] = resolve;
    setTimeout(function () {
      if (waiting[id]) {
        delete waiting[id];
        resolve({ decision: "unavailable", reason: "timeout", action: "none" });
      }
    }, 8000);
    try {
      port.postMessage(message);
    } catch (e) {
      delete waiting[id];
      resolve(Object.assign({}, UNAVAILABLE));
    }
  });
}

// -- clipboard (Firefox: in the background; Chromium: in an offscreen document) -------------------

async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  await chrome.offscreen.createDocument({
    url: "offscreen.html",
    reasons: ["CLIPBOARD"],
    justification: "Read and neutralise clipboard text that a web page wrote",
  });
}

async function readClipboard() {
  try {
    if (!IS_FIREFOX) {
      await ensureOffscreen();
      var r = await chrome.runtime.sendMessage({ target: "refmon-offscreen", op: "read" });
      return r && typeof r.text === "string" ? r.text : null;
    }
    return await navigator.clipboard.readText();
  } catch (e) {
    return null;
  }
}

async function writeClipboard(text) {
  try {
    if (!IS_FIREFOX) {
      await ensureOffscreen();
      await chrome.runtime.sendMessage({ target: "refmon-offscreen", op: "write", text: text });
      return;
    }
    await navigator.clipboard.writeText(text);
  } catch (e) {
    /* nothing more can be done; the banner still warns */
  }
}

// -- telling the user -----------------------------------------------------------------------------

function setDegraded(degraded) {
  try {
    quiet(api.action.setBadgeText({ text: degraded ? "!" : "" }));
    quiet(api.action.setTitle({
      title: degraded
        ? "Refmon: protection degraded (the Refmon program is not running)"
        : "Refmon: protection active",
    }));
  } catch (e) {
    /* ignore */
  }
}

function notify(title, message) {
  try {
    quiet(api.notifications.create({
      type: "basic",
      iconUrl: api.runtime.getURL("icon.png"),
      title: "Refmon: " + title,
      message: message,
    }));
  } catch (e) {
    /* ignore */
  }
}

function banner(tabId, data) {
  if (typeof tabId !== "number" || tabId < 0) return;
  try {
    quiet(api.tabs.sendMessage(tabId, Object.assign({ type: "refmon_banner" }, data), { frameId: 0 }));
  } catch (e) {
    /* tab gone */
  }
}

function familyName(ans) {
  return ans.family && ans.family.name ? ans.family.name : "Suspicious behaviour";
}

function familyAdvice(ans) {
  return ans.family && ans.family.advice ? ans.family.advice : "";
}

// -- acting on a decision ---------------------------------------------------------------------------

function startHold(ans, tabId, item) {
  var hold = ans.holds && ans.holds[0];
  if (!hold) return false;
  var timeout = Math.max(5, Number(ans.hold_timeout_s) || 60) * 1000;
  item.tabId = tabId;
  item.timer = setTimeout(function () {
    answerHold(hold.hold_id, "stop"); // timeout = deny
  }, timeout);
  holds[hold.hold_id] = item;
  banner(tabId, {
    level: "block",
    title: "Held: " + familyName(ans),
    body: item.what === "clipboard"
      ? "This page put a command on your clipboard that could harm this computer. It is held until you decide."
      : "This download is paused until you decide.",
    advice: familyAdvice(ans),
    hold_id: hold.hold_id,
    can_continue: !!hold.can_continue,
  });
  return true;
}

async function act(ans, tabId, item) {
  if (!ans || ans.error || ans.decision === "unavailable") {
    setDegraded(!ans || ans.decision === "unavailable");
    return;
  }
  setDegraded(false);
  var name = familyName(ans);
  switch (ans.action) {
    case "replace_clipboard":
      await writeClipboard(WARNING);
      notify("Blocked: " + name, "A command this page put on your clipboard was removed before it could run.");
      banner(tabId, {
        level: "block",
        title: "Blocked: " + name,
        body: "A command this page put on your clipboard was removed before it could run. You can keep browsing.",
        advice: familyAdvice(ans),
      });
      break;
    case "cancel_download":
      try {
        await api.downloads.cancel(item.downloadId);
      } catch (e) {
        /* already finished or gone */
      }
      notify("Blocked: " + name, "A download from a known bad place was stopped.");
      banner(tabId, { level: "block", title: "Blocked: " + name, body: "The download was stopped.", advice: familyAdvice(ans) });
      break;
    case "block_page":
      notify("Blocked: " + name, "This page is on a list of known bad places.");
      try {
        await api.tabs.update(tabId, { url: api.runtime.getURL("blocked.html") });
      } catch (e) {
        banner(tabId, { level: "block", title: "Blocked: " + name, body: "This page is on a list of known bad places.", advice: familyAdvice(ans) });
      }
      break;
    case "confirm":
      if (item.what === "clipboard") await writeClipboard(HELD);
      if (item.what === "download") {
        try {
          await api.downloads.pause(item.downloadId);
        } catch (e) {
          /* ignore */
        }
      }
      if (!startHold(ans, tabId, item)) {
        banner(tabId, { level: "warn", title: "Warning: " + name, body: ans.summary || "", advice: familyAdvice(ans) });
      }
      break;
    case "warn":
      notify("Warning: " + name, "Refmon would have stopped this, but runs in warning mode.");
      banner(tabId, { level: "warn", title: "Warning: " + name, body: ans.summary || "", advice: familyAdvice(ans) });
      break;
    default:
      break; // allow, or observe mode: nothing visible
  }
}

async function answerHold(holdId, answer) {
  var item = holds[holdId];
  if (!item) return;
  delete holds[holdId];
  clearTimeout(item.timer);
  var ans = await ask({ kind: "hold_answer", hold_id: holdId, answer: answer });
  var released = answer === "continue" && ans && !ans.error && ans.state === "released";
  if (item.what === "clipboard") {
    await writeClipboard(released ? item.text : WARNING);
  } else if (item.what === "download") {
    try {
      if (released) await api.downloads.resume(item.downloadId);
      else await api.downloads.cancel(item.downloadId);
    } catch (e) {
      /* ignore */
    }
  }
  item.text = null;
  try {
    quiet(api.tabs.sendMessage(item.tabId, { type: "refmon_banner_clear" }, { frameId: 0 }));
  } catch (e) {
    /* ignore */
  }
}

// -- observations -------------------------------------------------------------------------------

function cleanDomain(d) {
  d = String(d || "").toLowerCase().replace(/\.$/, "");
  return DOMAIN_RE.test(d) ? d : "";
}

async function onClipboardChanged(msg, sender) {
  var text = await readClipboard();
  if (!text || !text.trim() || text === WARNING || text === HELD) return;
  if (text === lastText) return; // the same text was judged a moment ago
  lastText = text;
  var selection = String(msg.selection || "").trim();
  var ans = await ask({
    kind: "clipboard_write",
    text: text.slice(0, 16384),
    domain: cleanDomain(msg.domain),
    user_selection: selection !== "" && selection === text.trim(),
  });
  await act(ans, sender.tab ? sender.tab.id : -1, { what: "clipboard", text: text });
}

async function onNavigated(msg, sender) {
  if (!settings.checkNavigation || !/^https?:/.test(String(msg.url || ""))) return;
  var ans = await ask({ kind: "navigate", url: String(msg.url).slice(0, 4096), domain: cleanDomain(msg.domain) });
  await act(ans, sender.tab ? sender.tab.id : -1, { what: "navigate" });
}

api.runtime.onMessage.addListener(function (msg, sender) {
  if (!msg || msg.target === "refmon-offscreen") return;
  if (msg.type === "clipboard_changed") onClipboardChanged(msg, sender);
  else if (msg.type === "navigated") onNavigated(msg, sender);
  else if (msg.type === "hold_answer" && typeof msg.hold_id === "string") {
    answerHold(msg.hold_id, msg.answer === "continue" ? "continue" : "stop");
  }
});

api.downloads.onCreated.addListener(async function (item) {
  if (!settings.checkDownloads) return;
  var url = String(item.finalUrl || item.url || "");
  if (!/^https?:/.test(url)) return;
  var domain = "";
  try {
    domain = cleanDomain(new URL(url).hostname);
  } catch (e) {
    return;
  }
  var ans = await ask({ kind: "download", url: url.slice(0, 4096), domain: domain });
  var tabs = [];
  try {
    tabs = await api.tabs.query({ active: true, lastFocusedWindow: true });
  } catch (e) {
    /* ignore */
  }
  await act(ans, tabs.length ? tabs[0].id : -1, { what: "download", downloadId: item.id });
});

loadSettings();
ask({ kind: "ping" }).then(function (ans) {
  setDegraded(!ans || ans.daemon !== "running");
});
