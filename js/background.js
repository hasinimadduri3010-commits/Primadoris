/* ============================================================
   PRIMADORIS — celestial background
   Pre-rendered nebula + planets on an offscreen canvas, with a
   live twinkling starfield, constellation threads and shooting
   stars drawn on top every frame.
   ============================================================ */
(function () {
  'use strict';

  var canvas = document.getElementById('space-canvas');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var W = 0;
  var H = 0;
  var dpr = 1;
  var stars = [];
  var brightStars = [];
  var constellations = [];
  var shooting = null;
  var nextShoot = 2600;
  var nebula = document.createElement('canvas');
  var nctx = nebula.getContext('2d');
  var panPhase = Math.random() * Math.PI * 2;

  /* ---------- helpers ---------- */
  function rand(min, max) {
    return min + Math.random() * (max - min);
  }

  function softBlob(c, x, y, r, color, alpha) {
    var g = c.createRadialGradient(x, y, 0, x, y, r);
    g.addColorStop(0, 'rgba(' + color + ',' + alpha + ')');
    g.addColorStop(0.42, 'rgba(' + color + ',' + alpha * 0.42 + ')');
    g.addColorStop(1, 'rgba(' + color + ',0)');
    c.fillStyle = g;
    c.beginPath();
    c.arc(x, y, r, 0, Math.PI * 2);
    c.fill();
  }

  function drawPlanet(c, o) {
    var x = o.x;
    var y = o.y;
    var r = o.r;

    /* outer atmosphere */
    var halo = c.createRadialGradient(x, y, r * 0.86, x, y, r * 1.38);
    halo.addColorStop(0, 'rgba(' + o.glow + ',' + (o.glowAlpha || 0.32) + ')');
    halo.addColorStop(0.5, 'rgba(' + o.glow + ',' + (o.glowAlpha || 0.32) * 0.4 + ')');
    halo.addColorStop(1, 'rgba(' + o.glow + ',0)');
    c.fillStyle = halo;
    c.beginPath();
    c.arc(x, y, r * 1.38, 0, Math.PI * 2);
    c.fill();

    /* rings (behind) */
    if (o.rings) {
      c.save();
      c.translate(x, y);
      c.rotate(o.ringTilt);
      for (var i = 0; i < 3; i++) {
        c.beginPath();
        c.ellipse(0, 0, r * (1.35 + i * 0.19), r * (0.28 + i * 0.07), 0, Math.PI * 0.06, Math.PI * 0.94, true);
        c.strokeStyle = 'rgba(' + o.ringColor + ',' + (0.2 - i * 0.05) + ')';
        c.lineWidth = 1.6 - i * 0.35;
        c.stroke();
      }
      c.restore();
    }

    /* body */
    var body = c.createRadialGradient(
      x - r * 0.42, y - r * 0.46, r * 0.1,
      x, y, r
    );
    body.addColorStop(0, o.lit);
    body.addColorStop(0.45, o.mid);
    body.addColorStop(0.82, o.dark);
    body.addColorStop(1, o.edge || o.dark);
    c.fillStyle = body;
    c.beginPath();
    c.arc(x, y, r, 0, Math.PI * 2);
    c.fill();

    /* surface bands */
    if (o.bands) {
      c.save();
      c.beginPath();
      c.arc(x, y, r, 0, Math.PI * 2);
      c.clip();
      for (var b = 0; b < 4; b++) {
        var by = y - r * 0.7 + b * r * 0.46;
        c.fillStyle = 'rgba(150,160,255,' + (0.035 + (b % 2) * 0.03) + ')';
        c.beginPath();
        c.ellipse(x, by, r * 1.05, r * 0.16, -0.12, 0, Math.PI * 2);
        c.fill();
      }
      c.restore();
    }

    /* rim light */
    c.save();
    c.beginPath();
    c.arc(x, y, r * 0.995, 0, Math.PI * 2);
    c.strokeStyle = 'rgba(' + o.glow + ',0.42)';
    c.lineWidth = 1.2;
    c.stroke();
    c.restore();

    /* rings (front half) */
    if (o.rings) {
      c.save();
      c.translate(x, y);
      c.rotate(o.ringTilt);
      for (var j = 0; j < 3; j++) {
        c.beginPath();
        c.ellipse(0, 0, r * (1.35 + j * 0.19), r * (0.28 + j * 0.07), 0, Math.PI * 0.94, Math.PI * 0.06, true);
        c.strokeStyle = 'rgba(' + o.ringColor + ',' + (0.26 - j * 0.06) + ')';
        c.lineWidth = 1.6 - j * 0.35;
        c.stroke();
      }
      c.restore();
    }
  }

  /* ---------- static painter ---------- */
  function paintNebula() {
    nebula.width = Math.max(1, Math.floor(W * Math.min(dpr, 1.5)));
    nebula.height = Math.max(1, Math.floor(H * Math.min(dpr, 1.5)));
    var s = nebula.width / W;
    nctx.setTransform(s, 0, 0, s, 0, 0);
    nctx.clearRect(0, 0, W, H);

    /* deep space base */
    var base = nctx.createLinearGradient(0, 0, W * 0.35, H);
    base.addColorStop(0, '#05061a');
    base.addColorStop(0.42, '#080b26');
    base.addColorStop(0.72, '#06081d');
    base.addColorStop(1, '#03040d');
    nctx.fillStyle = base;
    nctx.fillRect(0, 0, W, H);

    /* big violet nebula mass across the upper band */
    softBlob(nctx, W * 0.54, H * 0.10, Math.max(W, H) * 0.48, '116,86,232', 0.30);
    softBlob(nctx, W * 0.36, H * 0.24, Math.max(W, H) * 0.30, '86,102,232', 0.24);
    softBlob(nctx, W * 0.72, H * 0.20, Math.max(W, H) * 0.30, '150,96,232', 0.20);
    softBlob(nctx, W * 0.90, H * 0.36, Math.max(W, H) * 0.34, '70,78,210', 0.22);
    softBlob(nctx, W * 0.14, H * 0.52, Math.max(W, H) * 0.30, '74,62,180', 0.20);
    softBlob(nctx, W * 0.46, H * 0.52, Math.max(W, H) * 0.26, '96,70,200', 0.12);

    /* luminous core near the title */
    softBlob(nctx, W * 0.47, H * 0.055, Math.max(W, H) * 0.17, '196,186,255', 0.26);

    /* lower-left world glow */
    softBlob(nctx, W * 0.03, H * 0.86, Math.max(W, H) * 0.30, '132,104,255', 0.24);
    softBlob(nctx, W * 0.10, H * 0.60, Math.max(W, H) * 0.20, '86,96,220', 0.16);

    /* right-lower haze */
    softBlob(nctx, W * 0.86, H * 0.88, Math.max(W, H) * 0.26, '86,74,200', 0.15);

    /* dust filaments */
    nctx.save();
    nctx.globalCompositeOperation = 'lighter';
    for (var i = 0; i < 26; i++) {
      var fx = rand(0, W);
      var fy = rand(0, H * 0.75);
      var len = rand(W * 0.08, W * 0.32);
      var ang = rand(-0.5, 0.5);
      var grad = nctx.createLinearGradient(fx, fy, fx + Math.cos(ang) * len, fy + Math.sin(ang) * len);
      grad.addColorStop(0, 'rgba(140,150,255,0)');
      grad.addColorStop(0.5, 'rgba(150,140,255,' + rand(0.02, 0.06) + ')');
      grad.addColorStop(1, 'rgba(140,150,255,0)');
      nctx.strokeStyle = grad;
      nctx.lineWidth = rand(8, 34);
      nctx.beginPath();
      nctx.moveTo(fx, fy);
      nctx.quadraticCurveTo(
        fx + Math.cos(ang) * len * 0.5,
        fy + Math.sin(ang) * len * 0.5 - rand(10, 60),
        fx + Math.cos(ang) * len,
        fy + Math.sin(ang) * len
      );
      nctx.stroke();
    }
    nctx.restore();

    /* planets */
    drawPlanet(nctx, {
      x: W * 0.885, y: -H * 0.10, r: Math.max(150, Math.min(W, H) * 0.22),
      glow: '120,110,220', glowAlpha: 0.22, rings: true, ringTilt: -0.42,
      ringColor: '160,150,235',
      lit: 'rgba(96,104,178,0.95)', mid: 'rgba(46,50,104,0.96)', dark: 'rgba(12,14,40,0.98)', edge: 'rgba(8,9,26,1)'
    });

    drawPlanet(nctx, {
      x: -W * 0.045, y: H * 0.74, r: Math.max(120, Math.min(W, H) * 0.19),
      glow: '132,104,255', glowAlpha: 0.26, rings: false, bands: true,
      lit: 'rgba(82,66,168,0.9)', mid: 'rgba(38,30,96,0.95)', dark: 'rgba(10,9,32,1)', edge: 'rgba(6,6,20,1)'
    });

    drawPlanet(nctx, {
      x: W * 0.085, y: H * 1.03, r: Math.max(180, Math.min(W, H) * 0.30),
      glow: '150,120,255', glowAlpha: 0.30, rings: false, bands: true,
      lit: 'rgba(120,104,220,0.85)', mid: 'rgba(48,40,120,0.92)', dark: 'rgba(14,12,44,1)', edge: 'rgba(8,7,26,1)'
    });

    drawPlanet(nctx, {
      x: W * 1.02, y: H * 0.92, r: Math.max(90, Math.min(W, H) * 0.13),
      glow: '120,180,255', glowAlpha: 0.22, rings: true, ringTilt: 0.32,
      ringColor: '150,190,255',
      lit: 'rgba(96,140,200,0.8)', mid: 'rgba(40,58,120,0.9)', dark: 'rgba(10,14,44,1)', edge: 'rgba(6,8,26,1)'
    });

    /* vignette */
    var vig = nctx.createRadialGradient(W * 0.5, H * 0.42, Math.min(W, H) * 0.24, W * 0.5, H * 0.45, Math.max(W, H) * 0.86);
    vig.addColorStop(0, 'rgba(0,0,0,0)');
    vig.addColorStop(0.62, 'rgba(2,3,12,0.28)');
    vig.addColorStop(1, 'rgba(2,3,10,0.78)');
    nctx.fillStyle = vig;
    nctx.fillRect(0, 0, W, H);
  }

  function buildStars() {
    stars = [];
    brightStars = [];
    constellations = [];

    var count = Math.round(Math.min(560, (W * H) / 3400));
    for (var i = 0; i < count; i++) {
      var warm = Math.random() > 0.86;
      stars.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: rand(0.35, 1.55),
        base: rand(0.18, 0.72),
        amp: rand(0.1, 0.45),
        phase: rand(0, Math.PI * 2),
        speed: rand(0.35, 1.5),
        drift: rand(0.004, 0.03),
        color: warm ? '255,236,214' : (Math.random() > 0.6 ? '198,214,255' : '236,240,255')
      });
    }

    for (var b = 0; b < 12; b++) {
      brightStars.push({
        x: Math.random() * W,
        y: Math.random() * H * 0.9,
        r: rand(1.1, 1.9),
        phase: rand(0, Math.PI * 2),
        speed: rand(0.5, 1.2)
      });
    }

    /* constellation threads (static reference artwork) */
    for (var c = 0; c < 6; c++) {
      var pts = [];
      var px = rand(W * 0.04, W * 0.96);
      var py = rand(H * 0.06, H * 0.9);
      var segs = Math.round(rand(3, 5));
      for (var s = 0; s < segs; s++) {
        pts.push({ x: px, y: py });
        px += rand(-140, 160);
        py += rand(-90, 90);
      }
      constellations.push({ pts: pts, alpha: rand(0.06, 0.16) });
    }
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    paintNebula();
    buildStars();
  }

  /* ---------- frame loop ---------- */
  var t0 = performance.now();

  function frame(now) {
    var t = (now - t0) / 1000;

    /* nebula layer with a very slow parallax drift */
    ctx.clearRect(0, 0, W, H);
    var dx = Math.sin(t * 0.032 + panPhase) * 16;
    var dy = Math.cos(t * 0.024 + panPhase) * 10;
    var scale = 1.035;
    ctx.save();
    ctx.translate(W / 2 + dx, H / 2 + dy);
    ctx.scale(scale, scale);
    ctx.drawImage(nebula, -W / 2, -H / 2, W, H);
    ctx.restore();

    /* constellation threads */
    ctx.save();
    ctx.lineWidth = 1;
    for (var ci = 0; ci < constellations.length; ci++) {
      var co = constellations[ci];
      ctx.strokeStyle = 'rgba(178,186,255,' + co.alpha + ')';
      ctx.beginPath();
      for (var pi = 0; pi < co.pts.length; pi++) {
        var p = co.pts[pi];
        if (pi === 0) ctx.moveTo(p.x, p.y);
        else ctx.lineTo(p.x, p.y);
      }
      ctx.stroke();

      for (var pj = 0; pj < co.pts.length; pj++) {
        ctx.fillStyle = 'rgba(220,226,255,' + (co.alpha * 3.4) + ')';
        ctx.beginPath();
        ctx.arc(co.pts[pj].x, co.pts[pj].y, 1.3, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    ctx.restore();

    /* stars */
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (var i = 0; i < stars.length; i++) {
      var st = stars[i];
      var tw = reduceMotion ? st.base : st.base + Math.sin(t * st.speed + st.phase) * st.amp;
      if (tw <= 0.02) continue;
      var sy = st.y - (reduceMotion ? 0 : (t * st.drift) % H);
      if (sy < 0) sy += H;
      ctx.fillStyle = 'rgba(' + st.color + ',' + tw.toFixed(3) + ')';
      ctx.beginPath();
      ctx.arc(st.x, sy, st.r, 0, Math.PI * 2);
      ctx.fill();

      if (st.r > 1.25 && tw > 0.55) {
        ctx.fillStyle = 'rgba(' + st.color + ',' + (tw * 0.12).toFixed(3) + ')';
        ctx.beginPath();
        ctx.arc(st.x, sy, st.r * 3.4, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    /* bright stars with flares */
    for (var b = 0; b < brightStars.length; b++) {
      var bs = brightStars[b];
      var a = reduceMotion ? 0.85 : 0.6 + Math.sin(t * bs.speed + bs.phase) * 0.35;
      ctx.fillStyle = 'rgba(236,240,255,' + a.toFixed(3) + ')';
      ctx.beginPath();
      ctx.arc(bs.x, bs.y, bs.r, 0, Math.PI * 2);
      ctx.fill();

      ctx.strokeStyle = 'rgba(210,220,255,' + (a * 0.32).toFixed(3) + ')';
      ctx.lineWidth = 0.8;
      ctx.beginPath();
      ctx.moveTo(bs.x - bs.r * 4.2, bs.y);
      ctx.lineTo(bs.x + bs.r * 4.2, bs.y);
      ctx.moveTo(bs.x, bs.y - bs.r * 4.2);
      ctx.lineTo(bs.x, bs.y + bs.r * 4.2);
      ctx.stroke();
    }
    ctx.restore();

    /* shooting stars */
    if (!reduceMotion) {
      if (!shooting && now > nextShoot) {
        shooting = {
          x: rand(W * 0.1, W * 0.75),
          y: rand(H * 0.04, H * 0.4),
          vx: rand(280, 520),
          vy: rand(90, 190),
          life: 0,
          ttl: rand(0.9, 1.6)
        };
        nextShoot = now + rand(5200, 12000);
      }
      if (shooting) {
        var sh = shooting;
        sh.life += 1 / 60;
        var px = sh.x + sh.vx * sh.life;
        var py = sh.y + sh.vy * sh.life;
        var tailX = px - sh.vx * 0.16;
        var tailY = py - sh.vy * 0.16;
        var fade = Math.max(0, 1 - sh.life / sh.ttl);
        var lg = ctx.createLinearGradient(tailX, tailY, px, py);
        lg.addColorStop(0, 'rgba(180,200,255,0)');
        lg.addColorStop(1, 'rgba(226,236,255,' + (fade * 0.85).toFixed(3) + ')');
        ctx.strokeStyle = lg;
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.moveTo(tailX, tailY);
        ctx.lineTo(px, py);
        ctx.stroke();

        ctx.fillStyle = 'rgba(255,255,255,' + (fade * 0.95).toFixed(3) + ')';
        ctx.beginPath();
        ctx.arc(px, py, 1.7, 0, Math.PI * 2);
        ctx.fill();

        if (sh.life > sh.ttl) shooting = null;
      }
    }

    requestAnimationFrame(frame);
  }

  var rt;
  window.addEventListener('resize', function () {
    clearTimeout(rt);
    rt = setTimeout(resize, 140);
  });

  resize();
  requestAnimationFrame(frame);
})();
