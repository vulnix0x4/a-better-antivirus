# The app's page, in a browser (development and tests)

Nothing in this folder is shipped: the app embeds `../frontend` only.

- `server.mjs`: serves `../frontend` exactly as the app does (same
  Content-Security-Policy) and stands in for the two scripts Wails injects
  with `mock-bridge.js`, which serves the fixtures of
  `internal/appapi/testdata`. `npm run serve`, then open
  `http://127.0.0.1:8787/?home=frozen`. Query: `mode=locked`,
  `home=protected|frozen`, `alert=<fixture>` (`hostile`, `cannot-tell`, …),
  `screen=…`, `open=1` (as if started for the alert), `tier=full|light|none`,
  `reduced=1`, `fail=<action>`, `slow=1`, `empty=1`, `nosupport=1`, `update=1`.
- `ui.test.mjs`: the Playwright tests (`npm ci && npx playwright install
  chromium && npm test`; `CHANNEL=chrome` for a real GPU). CI:
  `.github/workflows/app-ui.yml`.
- `capture.mjs`: screenshots (`npm run shots`) and frame-exact videos
  (`npm run videos`, needs ffmpeg) of every screen; `OUT=<dir>`.

The page itself is plain ES modules (`../frontend/app.js` and `js/`), no
bundler. Its rules are in the head of `app.js` and checked by
`TestNoDangerousCalls` (`../app_test.go`) and the tests here.
