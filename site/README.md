# The website

Everything in this folder is the site, as it is served. There is no build step.

- `index.html` is the whole site: one page.
- `style.css` and `site.js` are its only stylesheet and script. The page works without the script.
- `404.html` is shown for addresses that don't exist.
- `_headers` sets the security headers on Cloudflare Pages.
- `media/` holds the demo video, its poster frame and the setup screenshot. They are copies of the files in `docs/`.

## Publishing

The site is uploaded to Cloudflare Pages as it is:

```
wrangler pages deploy site
```

To look at it first, serve this folder with any static file server and open it in a browser. Opening
`index.html` straight from disk works too.

## Rules

- **Nothing from other sites.** No analytics, no fonts, no scripts, no embeds. ABA promises no telemetry and
  the site keeps to it. The Content-Security-Policy in `_headers` enforces this: anything not served from
  this folder is blocked. Leave Cloudflare's Web Analytics switched off for the Pages project.
- **No inline scripts or styles** (`<script>…</script>`, `<style>`, `style="…"`). The policy blocks them.
- **Links inside the site are relative**, so it works on any address. `404.html` is the exception: its links
  start with `/`, because it is shown at any depth.
- **Text follows CONTRIBUTING.md:** plain words, short sentences. Don't claim anything the README doesn't.
- Keep every file under 25 MB (a Cloudflare Pages limit).

## Things that will change

- **When the installer is code-signed:** delete the block in `index.html` between `SMARTSCREEN BLOCK: START`
  and `SMARTSCREEN BLOCK: END`. The steps renumber themselves. Its styles are under "SmartScreen block" in
  `style.css`.
- **When there is a code signing policy page:** the footer of `index.html` has a commented-out link for it.
- **When another system is supported:** the download area is a list with one `<li class="platform">` per
  system. Change `is-soon` to `is-available` and give it a download button like the Windows one. `site.js`
  already recognises macOS and Linux visitors.
- **When the site has its final address:** link previews need a full address for the picture. Change
  `og:image` in `index.html` to `https://<address>/og.png` and add `og:url`.
- **When a new demo is recorded:** replace `media/demo.mp4` and `media/demo-poster.jpg`, and update the text
  version of the video under it in `index.html`.
