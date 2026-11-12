/* Original procedural icosphere. Canvas 2D, no GPU library or network dependency. */
(() => {
  "use strict";
  const canvas = document.getElementById("sphereCanvas");
  const stage = document.getElementById("sphereStage");
  const button = document.getElementById("motionButton");
  if (!canvas || !stage || !button) return;
  let ctx;
  try {
    ctx = canvas.getContext("2d", { alpha: true });
  } catch {
    return;
  }
  if (!ctx) return; // The local SVG stays visible if canvas is unavailable.

  const phi = (1 + Math.sqrt(5)) / 2;
  const normalize = (v) => {
    const length = Math.hypot(...v);
    return v.map((x) => x / length);
  };
  const vertices = [
    [-1, phi, 0],
    [1, phi, 0],
    [-1, -phi, 0],
    [1, -phi, 0],
    [0, -1, phi],
    [0, 1, phi],
    [0, -1, -phi],
    [0, 1, -phi],
    [phi, 0, -1],
    [phi, 0, 1],
    [-phi, 0, -1],
    [-phi, 0, 1],
  ].map(normalize);
  let faces = [
    [0, 11, 5],
    [0, 5, 1],
    [0, 1, 7],
    [0, 7, 10],
    [0, 10, 11],
    [1, 5, 9],
    [5, 11, 4],
    [11, 10, 2],
    [10, 7, 6],
    [7, 1, 8],
    [3, 9, 4],
    [3, 4, 2],
    [3, 2, 6],
    [3, 6, 8],
    [3, 8, 9],
    [4, 9, 5],
    [2, 4, 11],
    [6, 2, 10],
    [8, 6, 7],
    [9, 8, 1],
  ];
  // Two subdivisions: 162 vertices, 320 triangular faces, 480 shared edges.
  for (let level = 0; level < 2; level++) {
    const cache = new Map();
    function midpoint(a, b) {
      const key = a < b ? `${a}:${b}` : `${b}:${a}`;
      if (!cache.has(key)) {
        cache.set(key, vertices.length);
        vertices.push(
          normalize(vertices[a].map((v, i) => (v + vertices[b][i]) / 2)),
        );
      }
      return cache.get(key);
    }
    faces = faces.flatMap(([a, b, c]) => {
      const ab = midpoint(a, b),
        bc = midpoint(b, c),
        ca = midpoint(c, a);
      return [
        [a, ab, ca],
        [b, bc, ab],
        [c, ca, bc],
        [ab, bc, ca],
      ];
    });
  }
  const edgeMap = new Map();
  faces.forEach(([a, b, c]) =>
    [
      [a, b],
      [b, c],
      [c, a],
    ].forEach(([x, y]) =>
      edgeMap.set(x < y ? `${x}:${y}` : `${y}:${x}`, [x, y]),
    ),
  );
  const edges = [...edgeMap.values()];
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  let paused = reducedMotion.matches || Boolean(navigator.connection?.saveData);
  let visible = true,
    frame = null,
    lastTime = null,
    rotation = 0.45;
  let targetX = 0,
    targetY = 0,
    pointerX = 0,
    pointerY = 0,
    size = 600;
  const frameInterval =
    navigator.hardwareConcurrency <= 4 ? 1000 / 24 : 1000 / 30;

  function rotate([x, y, z]) {
    const ry = rotation + pointerX,
      rx = -0.22 + pointerY;
    const xx = x * Math.cos(ry) + z * Math.sin(ry);
    const zz = -x * Math.sin(ry) + z * Math.cos(ry);
    return [
      xx,
      y * Math.cos(rx) - zz * Math.sin(rx),
      y * Math.sin(rx) + zz * Math.cos(rx),
    ];
  }
  function project([x, y, z]) {
    const perspective = 4 / (4 - z);
    return [300 + x * 194 * perspective, 300 + y * 194 * perspective, z];
  }
  function draw() {
    ctx.clearRect(0, 0, 600, 600);
    const points = vertices.map((v) => project(rotate(v)));
    const glow = ctx.createRadialGradient(290, 285, 15, 300, 300, 218);
    glow.addColorStop(0, "rgba(67,181,180,0.035)");
    glow.addColorStop(0.65, "rgba(70,190,192,0.055)");
    glow.addColorStop(1, "rgba(70,190,192,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(65, 65, 470, 470);
    const sorted = faces
      .map((face, id) => ({
        face,
        id,
        z: face.reduce((sum, i) => sum + points[i][2], 0) / 3,
      }))
      .sort((a, b) => a.z - b.z);
    sorted.forEach(({ face, id, z }) => {
      const front = Math.max(0, z);
      ctx.beginPath();
      face.forEach((i, n) => {
        const p = points[i];
        if (n === 0) ctx.moveTo(p[0], p[1]);
        else ctx.lineTo(p[0], p[1]);
      });
      ctx.closePath();
      const accent = id % 19 === 0 || id % 31 === 0;
      ctx.fillStyle = `rgba(112,235,224,${0.004 + front * (accent ? 0.12 : 0.018)})`;
      ctx.fill();
    });
    edges.forEach(([a, b]) => {
      const p = points[a],
        q = points[b],
        depth = (p[2] + q[2]) / 2;
      ctx.beginPath();
      ctx.moveTo(p[0], p[1]);
      ctx.lineTo(q[0], q[1]);
      ctx.lineWidth = depth > 0 ? 0.85 : 0.55;
      ctx.strokeStyle =
        depth > 0
          ? `rgba(139,237,226,${0.26 + depth * 0.52})`
          : `rgba(70,135,151,${0.08 + (depth + 1) * 0.09})`;
      ctx.stroke();
    });
    points.forEach(([x, y, z], i) => {
      if (z < 0.08) return;
      ctx.beginPath();
      ctx.arc(x, y, i % 7 === 0 ? 2 : 1.1, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(183,255,242,${0.2 + z * 0.7})`;
      ctx.fill();
    });
    // Two orbital paths, independent of the triangulated surface.
    for (const [tilt, opacity] of [
      [0.3, 0.26],
      [-0.65, 0.14],
    ]) {
      ctx.beginPath();
      ctx.ellipse(300, 300, 239, 69, tilt, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(122,208,208,${opacity})`;
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }
    const angle = rotation * 0.7;
    const ox = Math.cos(angle) * 239,
      oy = Math.sin(angle) * 69;
    ctx.beginPath();
    ctx.arc(
      300 + ox * Math.cos(0.3) - oy * Math.sin(0.3),
      300 + ox * Math.sin(0.3) + oy * Math.cos(0.3),
      2.4,
      0,
      Math.PI * 2,
    );
    ctx.fillStyle = "#b7fff1";
    ctx.fill();
  }
  function shouldAnimate() {
    return !paused && visible && !document.hidden;
  }
  function tick(time) {
    frame = null;
    if (!shouldAnimate()) {
      lastTime = null;
      return;
    }
    if (lastTime === null || time - lastTime >= frameInterval) {
      const elapsed =
        lastTime === null ? 0 : Math.min((time - lastTime) / 1000, 0.08);
      rotation += elapsed * 0.095;
      pointerX += (targetX - pointerX) * 0.07;
      pointerY += (targetY - pointerY) * 0.07;
      draw();
      lastTime = time;
    }
    frame = requestAnimationFrame(tick);
  }
  function updateMotion() {
    if (frame !== null) {
      cancelAnimationFrame(frame);
      frame = null;
    }
    lastTime = null;
    button.setAttribute("aria-pressed", String(paused));
    const ru = document.documentElement.lang === "ru";
    document.getElementById("motionLabel").textContent = paused
      ? ru
        ? "Вращать"
        : "Rotate"
      : ru
        ? "Пауза"
        : "Pause";
    button.setAttribute(
      "aria-label",
      paused
        ? ru
          ? "Включить вращение сферы"
          : "Start sphere rotation"
        : ru
          ? "Приостановить вращение сферы"
          : "Pause sphere rotation",
    );
    button.querySelector(".motion-icon").textContent = paused ? "▷" : "Ⅱ";
    if (shouldAnimate()) frame = requestAnimationFrame(tick);
  }
  function resize() {
    const rect = canvas.getBoundingClientRect();
    size = Math.max(1, rect.width);
    // Limit pixel count even on high-density phones and 4K screens.
    const pixels = Math.min(
      1000,
      Math.round(size * Math.min(devicePixelRatio || 1, 1.5)),
    );
    canvas.width = canvas.height = pixels;
    ctx.setTransform(pixels / 600, 0, 0, pixels / 600, 0, 0);
    draw();
  }
  button.addEventListener("click", () => {
    paused = !paused;
    updateMotion();
  });
  reducedMotion.addEventListener("change", (event) => {
    paused = event.matches || Boolean(navigator.connection?.saveData);
    updateMotion();
  });
  document.addEventListener("visibilitychange", updateMotion);
  document.addEventListener("antios:language", updateMotion);
  stage.addEventListener(
    "pointermove",
    (event) => {
      if (paused || event.pointerType !== "mouse") return;
      const rect = canvas.getBoundingClientRect();
      targetX = ((event.clientX - rect.left) / size - 0.5) * 0.4;
      targetY = ((event.clientY - rect.top) / size - 0.5) * 0.25;
    },
    { passive: true },
  );
  stage.addEventListener("pointerleave", () => {
    targetX = targetY = 0;
  });
  if (typeof IntersectionObserver !== "undefined")
    new IntersectionObserver((entries) => {
      visible = entries[0].isIntersecting;
      updateMotion();
    }).observe(stage);
  if (typeof ResizeObserver !== "undefined")
    new ResizeObserver(resize).observe(canvas);
  else window.addEventListener("resize", resize, { passive: true });
  resize();
  stage.classList.add("canvas-ready");
  button.hidden = false;
  updateMotion();
})();
