// What the machine can draw, decided once.
//   full:   a real GPU. Bloom, glass ice, moving icons, blurred panels.
//   light:  software WebGL (a VM, Remote Desktop, no driver). The same scene
//           without the costly parts, at half the frame rate.
//   none:   no WebGL at all. A still backdrop and flat icons.
// Reduced motion (the system setting) keeps whichever scene but draws it
// still: one frame whenever something changes.

function probe() {
  try {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl2') || c.getContext('webgl');
    if (!gl) return { ok: false, renderer: '', vendor: '', software: true };
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = String(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
    const vendor = String(ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR));
    const software = /swiftshader|basic render|llvmpipe|warp|software|softpipe/i.test(renderer);
    const webgl2 = typeof WebGL2RenderingContext !== 'undefined' && gl instanceof WebGL2RenderingContext;
    gl.getExtension('WEBGL_lose_context')?.loseContext();
    return { ok: true, webgl2, renderer, vendor, software };
  } catch (e) {
    return { ok: false, renderer: '', vendor: '', software: true, error: String(e) };
  }
}

export const gl = probe();
const dev = window.__abaDev || {}; // set by the development bridge only
export const reduced = dev.reduced ?? matchMedia('(prefers-reduced-motion: reduce)').matches;
export const tier = dev.tier || (!gl.ok ? 'none' : gl.software ? 'light' : 'full');
// Frames are stepped by hand (tests, recordings) instead of by the clock.
export const manual = !!dev.manual;

document.documentElement.dataset.gfx = tier;
if (reduced) document.documentElement.dataset.still = '1';

// How many baits the web has room for (scene.js lays them out).
export const MAX_BAITS = 30;
