# The website

Everything in this folder is the site, exactly as it is served. There is no build step.

| File | What it is |
|---|---|
| `index.html` | The whole site: one page. Readable and complete without JavaScript. |
| `css/site.css` | The only stylesheet. Colours are tokens at the top; the light scheme redefines them. |
| `js/early.js` | One line that runs before first paint, so the page doesn't flash its no-JavaScript version. |
| `js/site.js` | Everything interactive. The page works without it. Makes no network requests. |
| `fonts/` | JetBrains Mono, subset to the characters the site uses (23 KB), with its licence (`OFL.txt`). |
| `media/` | The demo video and setup screenshot (copies of `docs/`), and a poster frame cut from the video. |
| `og.jpg` | The link-preview picture (from `docs/social-preview.png`). |
| `404.html` | Shown for addresses that don't exist. |
| `_headers` | Security headers on Cloudflare Pages, including the Content-Security-Policy. |

## What's on the page

1. **Be the stealer** (hero). A file list of a made-up PC, "Sam's", as a stealer sees it. Visitors grab files;
   opening a bait freezes them, with ice, a FROZEN stamp and an imitation of ABA's alert. Uploading without
   touching a bait "wins", and the page says why: that's ABA's first honest limitation. The freeze time is
   drawn from 72–151 ms, the range ABA measures in CI. Without JavaScript it's a plain list with baits marked.
   On first view, a ghost cursor plays one round by itself (not with reduced motion).
2. **Keep Defender on.** A full-width band. Don't remove it.
3. **The real video**, with a text version, and a reaction pad that compares the visitor to 158 ms.
4. **Why it works**, **How it works** (a slowed-down instant freeze, steps as a list beside it),
   **Honest limitations** (all of them), **Download**, **What it changes**.

Everything the game, the alert and the terminal say follows the README. If ABA's behaviour changes
(alert wording, presets, timings, what's a bait), update `index.html` and `js/site.js` to match.

## Publishing

Upload the folder to Cloudflare Pages as it is:

```
wrangler pages deploy site
```

To look at it first, serve this folder with any static file server. Leave Cloudflare's Web Analytics
switched off for the project.

## Rules

- **Nothing from other sites.** No analytics, fonts, scripts or embeds. The Content-Security-Policy in
  `_headers` blocks anything not served from here.
- **No inline scripts or styles** (`<script>…</script>`, `<style>`, `style="…"`). The policy blocks them.
  Setting `element.style` from `site.js` is fine.
- **Links inside the site are relative**, so it works on any address. `404.html` is the exception.
- **Text follows CONTRIBUTING.md:** plain words, short sentences. Claim nothing the README doesn't.
- Keep every file under 25 MB (a Cloudflare Pages limit).

## Things that will change

- **When the installer is code-signed:** delete the block in `index.html` between
  `UNSIGNED-INSTALLER BLOCK: START` and `UNSIGNED-INSTALLER BLOCK: END`. The steps renumber themselves. Its
  styles are under "Unsigned-installer block" in `css/site.css`.
- **Code signing policy page:** the footer of `index.html` has a commented-out link for it.
- **Another system:** the download area is a list with one `<li class="os">` per system. Change `is-soon`
  to `is-ready` and give it a download link like the Windows one. `site.js` already recognises macOS and
  Linux visitors.
- **Final address:** change `og:image` in `index.html` to `https://<address>/og.jpg` and add `og:url`.
- **New demo video:** replace `media/demo.mp4` and `media/demo-poster.webp`, and update the text version
  under the video in `index.html`.
- **Font:** to add characters, re-subset JetBrains Mono (variable, weights 400–800) with `pyftsubset`.
