# Setup's pictures

ABA-Setup.exe wears the ABA app's look: always dark, on ABA's near-black (`#0b0c0b`), with ABA's green
(`#6ee7a0`) and ice blue (`#a6dbff`).

| File | Where it shows |
|---|---|
| `welcome-<width>.png` | The tall picture on the first and the last page: ABA's ice gem over the tripwire web of baits. Its right edge fades into the page. |
| `header-<size>.png` | The gem in the top right corner of every other page. Transparent around the gem. |
| `aba-setup.ico` | ABA-Setup.exe's own icon and the window's: the ABA app's icon (`cmd/aba-app/winres/icon.png`). |

Each picture comes in several sizes, the ones Inno Setup's help lists for 100% to 250% scaling. `aba.iss`
names them all, and Setup picks the one that fits the screen, so nothing is blurry.

## Making them again

They are rendered with three.js, so a change of look is a change of numbers, not a redraw:

```sh
cd installer/art/src
npm install       # three and playwright, the versions in package.json
node render.mjs   # writes ../welcome-*.png and ../header-*.png
```

It needs Google Chrome, ImageMagick (`magick`) and `pngquant`. The scene is `scene.html`; camera, light and
glow are in `look.json`. Each picture is rendered at twice its size, shrunk, and saved as a palette PNG
(a third of the size, no visible difference). Together they add about 0.4 MB to Setup.
