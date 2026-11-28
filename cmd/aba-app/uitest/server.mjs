// Development server for the app's page: the files of ../frontend exactly as
// the app embeds them, with the same Content-Security-Policy, and the two
// scripts Wails injects (/wails/ipc.js, /wails/runtime.js) replaced by a mock
// bridge that serves the fixtures of internal/appapi/testdata.
//
//   node server.mjs [port]      then open http://127.0.0.1:<port>/?home=frozen
//
// Query: mode=full|locked  home=protected|frozen  alert=<fixture, e.g. hostile>
//        screen=home|caught|report|history|baits|settings  open=1 (as if started for the alert)
//        tier=full|light|none  reduced=1  manual=1  fail=<action kind>  slow=1
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FRONTEND = path.join(HERE, '..', 'frontend');
export const FIXTURES = path.join(HERE, '..', '..', '..', 'internal', 'appapi', 'testdata');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.json': 'application/json', '.png': 'image/png' };

// The same policy as cmd/aba-app/assets.go (contentSecurityPolicy).
export function csp(indexHTML) {
  const m = /<script type="importmap">([\s\S]*?)<\/script>/.exec(indexHTML);
  if (!m) throw new Error('index.html: no import map');
  const hash = crypto.createHash('sha256').update(m[1]).digest('base64');
  return "default-src 'none'; script-src 'self' 'sha256-" + hash + "'; style-src 'self'; font-src 'self'; img-src 'self'; " +
    "connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; " +
    "manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
}

function fixtures() {
  const out = {};
  for (const f of fs.readdirSync(FIXTURES)) if (f.endsWith('.json')) out[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(FIXTURES, f), 'utf8'));
  return out;
}

export function start(port = 0) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const index = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
    const headers = { 'Content-Security-Policy': csp(index), 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' };
    const send = (code, type, body) => { res.writeHead(code, { ...headers, 'content-type': type }); res.end(body); };
    if (url.pathname === '/favicon.ico') return send(204, 'image/x-icon', '');
    if (url.pathname === '/wails/ipc.js') return send(200, MIME['.js'], '// (Wails IPC: not here)\n');
    if (url.pathname === '/wails/runtime.js') return send(200, MIME['.js'], 'window.__FIXTURES = ' + JSON.stringify(fixtures()) + ';\n' + fs.readFileSync(path.join(HERE, 'mock-bridge.js'), 'utf8'));
    if (url.pathname === '/' || url.pathname === '/index.html') return send(200, MIME['.html'], index.replace('<head>', '<head><script src="/wails/ipc.js"></script><script src="/wails/runtime.js"></script>'));
    const file = path.normalize(path.join(FRONTEND, decodeURIComponent(url.pathname)));
    if (!file.startsWith(FRONTEND + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return send(404, 'text/plain', 'not found');
    send(200, MIME[path.extname(file)] || 'application/octet-stream', fs.readFileSync(file));
  });
  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}/`, close: () => new Promise(r => server.close(r)) })));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const s = await start(Number(process.argv[2]) || 8787);
  console.log('ABA app page (mock bridge): ' + s.url + '?home=frozen');
}
