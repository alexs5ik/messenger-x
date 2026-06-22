// Device detection for the Messenger X web client — classifies the runtime device
// (mobile phone / tablet / desktop) and exposes it to CSS via attributes on <html>.
//
// Why this module exists: the layout used to switch on width-only CSS media queries, which
// misreads small desktop windows as "phones" and large touch tablets as "desktops". Real device
// adaptation needs the *pointer* capability too — `(pointer: coarse)` / navigator.maxTouchPoints
// tell us a finger-driven screen apart from a mouse-driven one of the same width.
//
// We also work around the classic mobile-browser 100vh bug: on iOS/Android the URL bar shows and
// hides, changing window.innerHeight, so a CSS `height: 100vh` overshoots the visible area. We
// publish --app-vh = innerHeight * 0.01 on every recompute as a fallback unit (calc(var(--app-vh)
// * 100)) for browsers that lack 100dvh.
//
// All state lives on document.documentElement so CSS can react with [data-device="…"] selectors;
// app.ts keeps owning data-view independently. Pure browser APIs, no imports.

export type DeviceClass = "mobile" | "tablet" | "desktop";

// Last computed class, returned by deviceClass()/isMobile() without recomputing.
let current: DeviceClass = "desktop";

// Optional consumer callback, invoked only when the class actually changes.
let onChangeCb: ((d: DeviceClass) => void) | undefined;

// Pending rAF handle so we can debounce bursts of resize events into one recompute.
let pendingFrame: number | null = null;

/** Classify the current viewport using width + pointer capability. */
function classify(): DeviceClass {
  const coarse =
    window.matchMedia("(pointer: coarse)").matches || navigator.maxTouchPoints > 0;
  const width = window.innerWidth;

  if (width <= 700) return "mobile";
  if (width > 700 && width <= 1024 && coarse) return "tablet";
  return "desktop";
}

/** Recompute the device class, refresh the <html> attributes/vars, and fire onChange on change. */
function recompute(): void {
  const root = document.documentElement;
  const coarse =
    window.matchMedia("(pointer: coarse)").matches || navigator.maxTouchPoints > 0;

  const next = classify();

  root.setAttribute("data-device", next);
  root.setAttribute("data-touch", coarse ? "true" : "false");
  root.setAttribute(
    "data-orientation",
    window.innerWidth >= window.innerHeight ? "landscape" : "portrait"
  );

  // Mobile URL-bar fix: expose 1% of the visible viewport height as a CSS custom property.
  root.style.setProperty("--app-vh", `${window.innerHeight * 0.01}px`);

  if (next !== current) {
    current = next;
    onChangeCb?.(next);
  }
}

/** Debounced recompute: coalesce rapid resize/orientation events into a single rAF tick. */
function scheduleRecompute(): void {
  if (pendingFrame !== null) cancelAnimationFrame(pendingFrame);
  pendingFrame = requestAnimationFrame(() => {
    pendingFrame = null;
    recompute();
  });
}

/**
 * Initialize device detection: compute + apply attributes immediately, then listen for
 * resize, orientationchange, and (pointer: coarse) changes. Pass an optional callback to be
 * notified whenever the DeviceClass transitions.
 */
export function initDevice(onChange?: (d: DeviceClass) => void): void {
  onChangeCb = onChange;

  // Apply synchronously so the first paint already has the right layout.
  recompute();

  window.addEventListener("resize", scheduleRecompute);
  window.addEventListener("orientationchange", scheduleRecompute);
  window
    .matchMedia("(pointer: coarse)")
    .addEventListener("change", scheduleRecompute);
}

/** The last computed device class (cached; no recomputation). */
export function deviceClass(): DeviceClass {
  return current;
}

/** Convenience: true when the device is classified as a phone. */
export function isMobile(): boolean {
  return current === "mobile";
}
