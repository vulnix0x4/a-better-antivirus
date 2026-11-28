// Runs before app.js (a classic script, so it runs even when the module
// can't load): keeps page errors for the self-test, and if app.js never
// starts, says so to the Go side instead of leaving it to time out.
window.__abaErrors = [];
addEventListener('error', e => window.__abaErrors.push(String(e.message || e.type) + (e.filename ? ' @ ' + e.filename + ':' + e.lineno : '')), true);
addEventListener('unhandledrejection', e => window.__abaErrors.push('unhandled: ' + String(e.reason && e.reason.stack || e.reason)));
setTimeout(() => {
  if (window.__abaStarted) return;
  const api = window.go && window.go.main && window.go.main.API;
  if (api) api.SelftestDone(JSON.stringify({ error: 'app.js did not start', errors: window.__abaErrors, userAgent: navigator.userAgent }));
}, 45000);
