/* ============================================================
   PRIMADORIS — canvas instruments
   · behavioral signal (live multi-series wave)
   · output comparison (expected vs actual bars)
   · integrity radar gauge
   · variance sparkline
   Shares one animation loop and one state object.
   ============================================================ */
(function () {
  'use strict';

  var LEVELS = [
    { key: 'baseline', label: 'HEALTHY', integrity: 100, variance: 0.0, threat: 0.0, chaos: 0.0, barDrop: 3 },
    { key: 'low', label: 'DRIFT', integrity: 88, variance: 0.42, threat: 12.5, chaos: 0.55, barDrop: 6 },
    { key: 'medium', label: 'WATCH', integrity: 66, variance: 1.87, threat: 34.0, chaos: 1.15, barDrop: 12 },
    { key: 'high', label: 'UNSTABLE', integrity: 44, variance: 4.2, threat: 68.5, chaos: 1.9, barDrop: 17 },
    { key: 'critical', label: 'COMPROMISED', integrity: 18, variance: 9.6, threat: 96.0, chaos: 2.8, barDrop: 25 }
  ];

  var state = {
    level: 0,
    paused: false,
    integrity: 100,
    integrityTarget: 100,
    variance: 0,
    varianceTarget: 0,
    threat: 0,
    threatTarget: 0
  };

  window.PrimadorisState = state;
  window.PrimadorisLevels = LEVELS;
  window.SentinelState = state;
  window.SentinelLevels = LEVELS;

  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }
  function rand(a, b) { return a + Math.random() * (b - a); }

  /* ---------- canvas plumbing ---------- */
  function setup(canvas) {
    if (!canvas) return null;
    var ctx = canvas.getContext('2d');
    var api = { canvas: canvas, ctx: ctx, w: 0, h: 0, dpr: 1 };
    api.fit = function () {
      var rect = canvas.getBoundingClientRect();
      if (!rect || rect.width <= 0 || rect.height <= 0) return false;
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      var w = Math.round(rect.width);
      var h = Math.round(rect.height);
      if (w === api.w && h === api.h && dpr === api.dpr) return false;
      api.w = w; api.h = h; api.dpr = dpr;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      return true;
    };
    return api;
  }


  function smooth(ctx, pts) {
    if (!pts.length) return;
    ctx.moveTo(pts[0].x, pts[0].y);
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i - 1] || pts[i];
      var p1 = pts[i];
      var p2 = pts[i + 1];
      var p3 = pts[i + 2] || p2;
      var c1x = p1.x + (p2.x - p0.x) / 6;
      var c1y = p1.y + (p2.y - p0.y) / 6;
      var c2x = p2.x - (p3.x - p1.x) / 6;
      var c2y = p2.y - (p3.y - p1.y) / 6;
      ctx.bezierCurveTo(c1x, c1y, c2x, c2y, p2.x, p2.y);
    }
  }

  function roundRect(ctx, x, y, w, h, r) {
    var rr = Math.min(r, w / 2, h / 2);
    ctx.beginPath();
    ctx.moveTo(x + rr, y);
    ctx.lineTo(x + w - rr, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
    ctx.lineTo(x + w, y + h);
    ctx.lineTo(x, y + h);
    ctx.lineTo(x, y + rr);
    ctx.quadraticCurveTo(x, y, x + rr, y);
    ctx.closePath();
  }

  /* ============================================================
     BEHAVIORAL SIGNAL
     ============================================================ */
  var signalCanvas = document.getElementById('signal-chart');
  var SIGNAL_N = 96;

  var SERIES = [
    { color: '214,224,255', width: 2.1, base: 2.45, amp: 0.62, f1: 0.115, f2: 0.255, f3: 0.44, p1: 0.0, p2: 1.4, p3: 3.1, area: 0.10 },
    { color: '139,116,255', width: 2.4, base: 2.05, amp: 0.92, f1: 0.082, f2: 0.191, f3: 0.36, p1: 1.9, p2: 4.2, p3: 0.6, area: 0.16 },
    { color: '95,130,255', width: 2.0, base: 2.75, amp: 0.72, f1: 0.146, f2: 0.311, f3: 0.52, p1: 3.6, p2: 0.9, p3: 2.4, area: 0.11 },
    { color: '189,123,240', width: 2.2, base: 1.72, amp: 1.02, f1: 0.061, f2: 0.168, f3: 0.29, p1: 5.2, p2: 2.7, p3: 4.6, area: 0.15 }
  ];

  var signalData = [];
  var sampleIndex = 0;

  function newSample(cfg, i, chaos) {
    var v = cfg.base
      + cfg.amp * Math.sin(i * cfg.f1 + cfg.p1)
      + cfg.amp * 0.52 * Math.sin(i * cfg.f2 + cfg.p2)
      + cfg.amp * 0.28 * Math.sin(i * cfg.f3 + cfg.p3)
      + (Math.random() - 0.5) * (0.18 + chaos * 0.42)
      + chaos * 0.22 * Math.sin(i * 0.7 + cfg.p1);
    return clamp(v, 0.06, 5);
  }

  function seedSignal() {
    signalData = SERIES.map(function () { return []; });
    for (var i = 0; i < SIGNAL_N; i++) {
      for (var s = 0; s < SERIES.length; s++) {
        signalData[s].push(newSample(SERIES[s], i, 0));
      }
    }
    sampleIndex = SIGNAL_N;
  }

  function stepSignal() {
    var chaos = LEVELS[state.level].chaos;
    for (var s = 0; s < SERIES.length; s++) {
      var arr = signalData[s];
      arr.push(newSample(SERIES[s], sampleIndex, chaos));
      if (arr.length > SIGNAL_N) arr.shift();
    }
    sampleIndex++;
  }

  var signalApi = signalCanvas ? setup(signalCanvas) : null;

  function drawSignal() {
    if (!signalApi) return;
    var ctx = signalApi.ctx;
    var w = signalApi.w;
    var h = signalApi.h;
    if (w < 20 || h < 20) return;  /* hidden or not yet measured */
    ctx.clearRect(0, 0, w, h);

    var padL = 34, padR = 10, padT = 12, padB = 24;
    var iw = Math.max(10, w - padL - padR);
    var ih = Math.max(10, h - padT - padB);
    var maxV = 5;

    function yOf(v) { return padT + ih - (v / maxV) * ih; }
    function xOf(i) { return padL + (i / (SIGNAL_N - 1)) * iw; }

    /* horizontal grid + labels */
    ctx.font = '9px "JetBrains Mono", ui-monospace, monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    [0, 2.5, 5].forEach(function (v) {
      var y = yOf(v);
      ctx.strokeStyle = v === 0 ? 'rgba(150,165,240,0.22)' : 'rgba(150,165,240,0.10)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y + 0.5);
      ctx.lineTo(w - padR, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = 'rgba(154,164,205,0.8)';
      ctx.fillText(v.toFixed(1), padL - 9, y);
    });

    /* vertical grid + time labels */
    var labels = ['-60s', '-45s', '-30s', '-15s', 'Now'];
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    labels.forEach(function (label, idx) {
      var x = padL + (idx / (labels.length - 1)) * iw;
      ctx.strokeStyle = 'rgba(150,165,240,0.07)';
      ctx.beginPath();
      ctx.moveTo(x + 0.5, padT);
      ctx.lineTo(x + 0.5, padT + ih);
      ctx.stroke();
      ctx.fillStyle = 'rgba(154,164,205,0.72)';
      ctx.fillText(label, x, padT + ih + 7);
    });

    /* series */
    ctx.save();
    ctx.beginPath();
    ctx.rect(padL - 2, padT - 6, iw + 4, ih + 10);
    ctx.clip();

    for (var s = 0; s < SERIES.length; s++) {
      var cfg = SERIES[s];
      var arr = signalData[s];
      if (!arr || arr.length < 2) continue;

      var pts = arr.map(function (v, i) {
        var cleanV = isFinite(v) ? v : 2.5;
        return { x: xOf(i), y: yOf(cleanV) };
      });

      /* area */
      var areaGrad = ctx.createLinearGradient(0, padT, 0, Math.max(padT + 1, padT + ih));
      areaGrad.addColorStop(0, 'rgba(' + cfg.color + ',' + cfg.area + ')');
      areaGrad.addColorStop(1, 'rgba(' + cfg.color + ',0)');
      ctx.beginPath();
      smooth(ctx, pts);
      ctx.lineTo(pts[pts.length - 1].x, padT + ih);
      ctx.lineTo(pts[0].x, padT + ih);
      ctx.closePath();
      ctx.fillStyle = areaGrad;
      ctx.fill();

      /* stroke */
      ctx.beginPath();
      smooth(ctx, pts);
      ctx.lineWidth = cfg.width;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.strokeStyle = 'rgba(' + cfg.color + ',0.92)';
      ctx.shadowColor = 'rgba(' + cfg.color + ',0.75)';
      ctx.shadowBlur = 14;
      ctx.stroke();
      ctx.shadowBlur = 0;

      /* bright core for the primary line */
      if (s === 0) {
        ctx.beginPath();
        smooth(ctx, pts);
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(255,255,255,0.5)';
        ctx.stroke();
      }
    }
    ctx.restore();
  }

  /* ============================================================
     OUTPUT COMPARISON
     ============================================================ */
  var compareCanvas = document.getElementById('compare-chart');
  var compareApi = compareCanvas ? setup(compareCanvas) : null;
  var EXPECTED = [45, 42, 40, 43, 41];
  var actualValues = EXPECTED.slice();

  function drawCompare() {
    if (!compareApi) return;
    var ctx = compareApi.ctx;
    var w = compareApi.w;
    var h = compareApi.h;
    if (w < 20 || h < 20) return;  /* hidden or not yet measured */
    ctx.clearRect(0, 0, w, h);

    var padL = 26, padR = 8, padT = 12, padB = 24;
    var iw = Math.max(10, w - padL - padR);
    var ih = Math.max(10, h - padT - padB);
    var maxV = 60;

    function yOf(v) { return padT + ih - (v / maxV) * ih; }

    ctx.font = '9px "JetBrains Mono", ui-monospace, monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    [0, 20, 40, 60].forEach(function (v) {
      var y = yOf(v);
      ctx.strokeStyle = v === 0 ? 'rgba(150,165,240,0.22)' : 'rgba(150,165,240,0.09)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(padL, y + 0.5);
      ctx.lineTo(w - padR, y + 0.5);
      ctx.stroke();
      ctx.fillStyle = 'rgba(154,164,205,0.78)';
      ctx.fillText(String(v), padL - 8, y);
    });

    var groups = EXPECTED.length;
    var groupW = iw / groups;
    var barW = Math.min(15, groupW * 0.24);
    var gap = Math.max(3, groupW * 0.05);

    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    for (var g = 0; g < groups; g++) {
      var cx = padL + groupW * (g + 0.5);

      /* group hover background */
      ctx.fillStyle = 'rgba(120,140,255,0.035)';
      roundRect(ctx, cx - groupW * 0.44, padT, groupW * 0.88, ih, 5);
      ctx.fill();

      var pairs = [
        { v: EXPECTED[g], from: '#8fa6ff', to: '#4c62d6', x: cx - barW - gap / 2 },
        { v: actualValues[g], from: '#f0b1ea', to: '#a95fc4', x: cx + gap / 2 }
      ];

      for (var p = 0; p < pairs.length; p++) {
        var pd = pairs[p];
        var val = isFinite(pd.v) ? pd.v : 2;
        var top = yOf(val);
        var bh = Math.max(2, padT + ih - top);
        var gradY2 = Math.max(top + 1, padT + ih);

        var grad = ctx.createLinearGradient(0, top, 0, gradY2);
        grad.addColorStop(0, pd.from);
        grad.addColorStop(1, pd.to);

        ctx.save();
        ctx.shadowColor = p === 0 ? 'rgba(110,140,255,0.55)' : 'rgba(226,150,235,0.5)';
        ctx.shadowBlur = 12;
        ctx.fillStyle = grad;
        roundRect(ctx, pd.x, top, barW, bh, 3);
        ctx.fill();
        ctx.restore();

        /* top highlight */
        ctx.fillStyle = 'rgba(255,255,255,0.28)';
        roundRect(ctx, pd.x, top, barW, 1.6, 1);
        ctx.fill();
      }

      ctx.fillStyle = 'rgba(178,188,222,0.9)';
      ctx.fillText('P' + (g + 1), cx, padT + ih + 7);
    }
  }

  /* ============================================================
     INTEGRITY RADAR GAUGE
     ============================================================ */
  var gaugeCanvas = document.getElementById('integrity-gauge');
  var gaugeApi = gaugeCanvas ? setup(gaugeCanvas) : null;

  function drawGauge() {
    if (!gaugeApi) return;
    var ctx = gaugeApi.ctx;
    var w = gaugeApi.w;
    var h = gaugeApi.h;
    if (w < 20 || h < 20) return;
    ctx.clearRect(0, 0, w, h);

    var cx = w / 2;
    var cy = h / 2;
    var r = Math.min(w, h) / 2 - 12;
    var pct = clamp(isFinite(state.integrity) ? state.integrity : 100, 0, 100) / 100;

    /* outer haze */
    var haze = ctx.createRadialGradient(cx, cy, r * 0.55, cx, cy, r * 1.16);
    haze.addColorStop(0, 'rgba(104,232,224,0.16)');
    haze.addColorStop(1, 'rgba(104,232,224,0)');
    ctx.fillStyle = haze;
    ctx.beginPath();
    ctx.arc(cx, cy, r * 1.16, 0, Math.PI * 2);
    ctx.fill();

    /* tick ring */
    ctx.save();
    ctx.translate(cx, cy);
    for (var t = 0; t < 72; t++) {
      var a = (t / 72) * Math.PI * 2 - Math.PI / 2;
      var on = t / 72 <= pct;
      var r1 = r + 4;
      var r2 = r + (on ? 8 : 6);
      ctx.strokeStyle = on ? 'rgba(126,240,216,0.55)' : 'rgba(140,160,220,0.16)';
      ctx.lineWidth = on ? 1.4 : 1;
      ctx.beginPath();
      ctx.moveTo(Math.cos(a) * r1, Math.sin(a) * r1);
      ctx.lineTo(Math.cos(a) * r2, Math.sin(a) * r2);
      ctx.stroke();
    }
    ctx.restore();

    /* track */
    ctx.beginPath();
    ctx.arc(cx, cy, r - 6, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(120,140,220,0.14)';
    ctx.lineWidth = 9;
    ctx.stroke();

    /* progress */
    if (pct > 0.001) {
      var start = -Math.PI / 2;
      var end = start + Math.PI * 2 * pct;
      var grad = ctx.createLinearGradient(cx - r, cy - r, cx + r, cy + r);
      grad.addColorStop(0, '#a8f5e6');
      grad.addColorStop(0.45, '#6fe8dc');
      grad.addColorStop(1, '#49c9d8');

      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, r - 6, start, end);
      ctx.lineWidth = 9;
      ctx.lineCap = 'round';
      ctx.strokeStyle = grad;
      ctx.shadowColor = 'rgba(110,232,220,0.75)';
      ctx.shadowBlur = 16;
      ctx.stroke();
      ctx.restore();
    }

    /* inner disc */
    var disc = ctx.createRadialGradient(cx, cy - r * 0.3, r * 0.1, cx, cy, r - 12);
    disc.addColorStop(0, 'rgba(20,46,54,0.9)');
    disc.addColorStop(1, 'rgba(9,14,34,0.95)');
    ctx.beginPath();
    ctx.arc(cx, cy, r - 13, 0, Math.PI * 2);
    ctx.fillStyle = disc;
    ctx.fill();
    ctx.strokeStyle = 'rgba(120,220,215,0.22)';
    ctx.lineWidth = 1;
    ctx.stroke();

    /* labels */
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#ffffff';
    ctx.font = '600 25px "Inter", system-ui, sans-serif';
    ctx.shadowColor = 'rgba(140,240,230,0.5)';
    ctx.shadowBlur = 14;
    var dispInteg = Math.round(isFinite(state.integrity) ? state.integrity : 100);
    ctx.fillText(dispInteg + '%', cx, cy - 4);
    ctx.shadowBlur = 0;

    ctx.fillStyle = 'rgba(168,200,208,0.85)';
    ctx.font = '500 7.5px "Inter", system-ui, sans-serif';
    var label = 'INTEGRITY';
    ctx.save();
    ctx.translate(cx, cy + 16);
    var sp = 0;
    for (var c = 0; c < label.length; c++) {
      var chw = ctx.measureText(label[c]).width;
      sp += chw + 2.2;
    }
    ctx.translate(-sp / 2, 0);
    ctx.textAlign = 'left';
    for (var k = 0; k < label.length; k++) {
      ctx.fillText(label[k], 0, 0);
      ctx.translate(ctx.measureText(label[k]).width + 2.2, 0);
    }
    ctx.restore();
  }

  /* ============================================================
     VARIANCE SPARKLINE
     ============================================================ */
  var sparkCanvas = document.getElementById('sparkline');
  var sparkApi = sparkCanvas ? setup(sparkCanvas) : null;
  var sparkData = [];

  function seedSpark() {
    sparkData = [];
    for (var i = 0; i < 60; i++) {
      sparkData.push(0.55 * Math.sin(i * 0.22) + 0.3 * Math.sin(i * 0.63 + 1.2) + rand(-0.12, 0.12));
    }
  }

  function drawSpark() {
    if (!sparkApi) return;
    var ctx = sparkApi.ctx;
    var w = sparkApi.w;
    var h = sparkApi.h;
    if (w < 10 || h < 10) return;
    ctx.clearRect(0, 0, w, h);

    var curLvl = Math.max(0, Math.min(LEVELS.length - 1, state.level || 0));
    var amp = h * 0.3 * (1 + curLvl * 0.35);
    var mid = h / 2;
    var pts = sparkData.map(function (v, i) {
      var cleanV = isFinite(v) ? v : 0;
      return { x: (i / (sparkData.length - 1)) * w, y: mid - cleanV * amp };
    });

    var grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(155,140,255,0.30)');
    grad.addColorStop(1, 'rgba(155,140,255,0)');
    ctx.beginPath();
    smooth(ctx, pts);
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    smooth(ctx, pts);
    ctx.lineWidth = 1.8;
    ctx.lineCap = 'round';
    ctx.strokeStyle = 'rgba(198,190,255,0.95)';
    ctx.shadowColor = 'rgba(155,140,255,0.85)';
    ctx.shadowBlur = 10;
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  /* ============================================================
     LOOP
     ============================================================ */
  seedSignal();
  seedSpark();

  function fitAll() {
    var changed = false;
    if (signalApi && signalApi.fit()) changed = true;
    if (compareApi && compareApi.fit()) changed = true;
    if (gaugeApi && gaugeApi.fit()) changed = true;
    if (sparkApi && sparkApi.fit()) changed = true;
    return changed;
  }

  // Initial measurement
  fitAll();

  // ResizeObserver on canvas wrappers for glitch-free sizing
  if (typeof ResizeObserver !== 'undefined') {
    var ro = new ResizeObserver(function () {
      fitAll();
    });
    [signalCanvas, compareCanvas, gaugeCanvas, sparkCanvas].forEach(function (c) {
      if (c && c.parentElement) ro.observe(c.parentElement);
    });
  }

  window.addEventListener('resize', function () {
    fitAll();
  });

  var last = performance.now();
  var signalClock = 0;
  var sparkClock = 0;
  var compareClock = 0;

  function loop(now) {
    var dt = Math.min(0.06, (now - last) / 1000);
    last = now;

    /* smooth the displayed metrics toward their targets */
    var dtClamped = isFinite(dt) ? dt : 0.016;
    var k = 1 - Math.exp(-dtClamped * 5.5);
    if (isFinite(state.integrityTarget)) state.integrity += (state.integrityTarget - state.integrity) * k;
    if (isFinite(state.varianceTarget))  state.variance  += (state.varianceTarget  - state.variance)  * k;
    if (isFinite(state.threatTarget))    state.threat    += (state.threatTarget    - state.threat)    * k;

    if (!state.paused) {
      signalClock += dt;
      sparkClock += dt;
      compareClock += dt;

      if (signalClock > 0.075) {
        signalClock = 0;
        stepSignal();
      }
      if (sparkClock > 0.13) {
        sparkClock = 0;
        sparkData.push(0.55 * Math.sin(sampleIndex * 0.22) + 0.3 * Math.sin(sampleIndex * 0.63 + 1.2) + rand(-0.12, 0.12));
        if (sparkData.length > 60) sparkData.shift();
      }
      if (compareClock > 0.55) {
        compareClock = 0;
        var curLvl = Math.max(0, Math.min(LEVELS.length - 1, state.level || 0));
        var drop = LEVELS[curLvl].barDrop || 3;
        for (var i = 0; i < actualValues.length; i++) {
          var target = EXPECTED[i] - drop + rand(-1.6, 1.6);
          actualValues[i] += (target - actualValues[i]) * 0.4;
          actualValues[i] = clamp(actualValues[i], 2, EXPECTED[i] + 2);
        }
      }
    }

    drawSignal();
    drawCompare();
    drawGauge();
    drawSpark();

    requestAnimationFrame(loop);
  }

  requestAnimationFrame(loop);

  /* Public API: call this whenever charts become visible after being hidden */
  window.PrimadorisCharts = {
    fitAll: fitAll,
    invalidate: function () {
      setTimeout(fitAll, 16);
      setTimeout(fitAll, 120);
    }
  };
})();
