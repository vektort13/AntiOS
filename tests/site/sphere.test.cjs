const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const source = fs.readFileSync(
  path.join(__dirname, "../../docs/sphere.js"),
  "utf8",
);

// A canvas/observer boundary harness: execute the real script and assert its
// observable resource policy, without a browser or third-party test runtime.
function load(options = {}) {
  const events = new Map(),
    frames = new Map(),
    attributes = new Map(),
    classes = new Set();
  const handlers = (target) => ({
    addEventListener(name, fn) {
      events.set(`${target}:${name}`, fn);
    },
  });
  let count = 0,
    id = 0;
  const context = new Proxy(
    {},
    {
      get(_, key) {
        if (key === "createRadialGradient")
          return () => ({ addColorStop() {} });
        return (...args) => {
          args
            .filter((arg) => typeof arg === "number")
            .forEach((n) =>
              assert.ok(
                Number.isFinite(n),
                `${key} received a nonfinite coordinate`,
              ),
            );
          if (key === "clearRect") count++;
        };
      },
      set() {
        return true;
      },
    },
  );
  const canvas = {
    width: 600,
    height: 600,
    getContext() {
      if (options.throwCanvas) throw Error("unavailable");
      return options.noCanvas ? null : context;
    },
    getBoundingClientRect() {
      return { width: options.width || 600, left: 0, top: 0 };
    },
  };
  const label = { textContent: "" },
    icon = { textContent: "" };
  const button = {
    ...handlers("button"),
    hidden: true,
    setAttribute(key, value) {
      attributes.set(key, value);
    },
    querySelector() {
      return icon;
    },
  };
  const stage = {
    ...handlers("stage"),
    classList: {
      add(name) {
        classes.add(name);
      },
    },
  };
  const document = {
    ...handlers("document"),
    documentElement: { lang: "ru" },
    hidden: false,
    getElementById(id) {
      return {
        sphereCanvas: canvas,
        sphereStage: stage,
        motionButton: button,
        motionLabel: label,
      }[id];
    },
  };
  const media = { ...handlers("media"), matches: Boolean(options.reduced) };
  const sandbox = {
    document,
    window: handlers("window"),
    navigator: {
      hardwareConcurrency: 8,
      connection: { saveData: options.saveData },
    },
    devicePixelRatio: options.dpr || 1,
    matchMedia: () => media,
    requestAnimationFrame(fn) {
      frames.set(++id, fn);
      return id;
    },
    cancelAnimationFrame(id) {
      frames.delete(id);
    },
    IntersectionObserver: class {
      constructor(fn) {
        events.set("intersection", fn);
      }
      observe() {}
    },
    ResizeObserver: class {
      observe() {}
    },
  };
  vm.runInNewContext(source, sandbox, { timeout: 3000 });
  return {
    canvas,
    button,
    document,
    attributes,
    classes,
    label,
    frames,
    get draws() {
      return count;
    },
    emit(name, event) {
      events.get(name)(event);
    },
    frame(time) {
      const queued = [...frames.values()];
      frames.clear();
      queued.forEach((fn) => fn(time));
    },
  };
}

test("unavailable canvas preserves the SVG and hides animation controls", () => {
  for (const options of [{ noCanvas: true }, { throwCanvas: true }]) {
    const page = load(options);
    assert.equal(page.frames.size, 0);
    assert.equal(page.button.hidden, true);
    assert.equal(page.classes.has("canvas-ready"), false);
  }
});
test("reduced motion renders one static frame until explicitly enabled", () => {
  const page = load({ reduced: true });
  assert.equal(page.draws, 1);
  assert.equal(page.frames.size, 0);
  assert.equal(page.attributes.get("aria-pressed"), "true");
  page.emit("button:click");
  assert.equal(page.frames.size, 1);
  page.frame(0);
  assert.equal(page.draws, 2);
  page.emit("button:click");
  assert.equal(page.frames.size, 0);
});
test("data saver starts without continuous animation", () => {
  const page = load({ saveData: true });
  assert.equal(page.draws, 1);
  assert.equal(page.frames.size, 0);
});
test("offscreen animation stops and resumes with a single loop", () => {
  const page = load();
  assert.equal(page.frames.size, 1);
  page.emit("intersection", [{ isIntersecting: false }]);
  assert.equal(page.frames.size, 0);
  page.emit("intersection", [{ isIntersecting: true }]);
  page.emit("intersection", [{ isIntersecting: true }]);
  assert.equal(page.frames.size, 1);
});
test("a background tab has no scheduled animation frames", () => {
  const page = load();
  page.document.hidden = true;
  page.emit("document:visibilitychange");
  assert.equal(page.frames.size, 0);
  page.document.hidden = false;
  page.emit("document:visibilitychange");
  assert.equal(page.frames.size, 1);
});
test("canvas resolution is capped on large and high-density displays", () => {
  const page = load({ width: 4000, dpr: 8 });
  assert.equal(page.canvas.width, 1000);
  assert.equal(page.canvas.height, 1000);
});
test("rendering is throttled and coordinates stay finite over time", () => {
  const page = load();
  page.frame(0);
  const initial = page.draws;
  page.frame(16);
  assert.equal(page.draws, initial);
  page.frame(40);
  assert.equal(page.draws, initial + 1);
  page.emit("stage:pointermove", {
    pointerType: "mouse",
    clientX: 40,
    clientY: 50,
  });
  for (let time = 80; time < 12_000; time += 40) page.frame(time);
  assert.equal(page.frames.size, 1);
});
test("motion preference changes cancel an already running loop", () => {
  const page = load();
  page.emit("media:change", { matches: true });
  assert.equal(page.frames.size, 0);
});
test("motion labels follow language changes without duplicating loops", () => {
  const page = load();
  assert.equal(page.label.textContent, "Пауза");
  page.document.documentElement.lang = "en";
  page.emit("document:antios:language");
  assert.equal(page.label.textContent, "Pause");
  assert.equal(page.frames.size, 1);
});
