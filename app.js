/* ============================================================
   PRIMADORIS — dashboard controller
   Manages: clock · uptime · nav panels · controls · API sync
   ============================================================ */
(function () {
  'use strict';

  var state = window.PrimadorisState || window.SentinelState;
  var LEVELS = window.PrimadorisLevels || window.SentinelLevels;
  if (!state || !LEVELS) return;

  var $ = function (id) { return document.getElementById(id); };

  /* ============================================================
     THREAT LEVEL COPY — maps index 0..4 to display strings
     ============================================================ */
  var COPY = [
    { meta: 'No anomalies detected',      threat: 'Low risk',      integ: 'Model stable',       danger: 'NONE',     status: 'Healthy',     weight: '1.500', attack: 'Clean Baseline',                       drift: 0,  quarantine: 0,  critical: 0,  tone: '' },
    { meta: 'Subtle drift detected',       threat: 'Low risk',      integ: 'Minor drift observed', danger: 'LOW',    status: 'Drift',       weight: '1.612', attack: 'Stealth Gradient Drift',               drift: 12, quarantine: 0,  critical: 0,  tone: 'is-warn' },
    { meta: 'Deviation above baseline',    threat: 'Moderate risk', integ: 'Investigating drift',  danger: 'MEDIUM', status: 'Suspicious',  weight: '1.884', attack: 'Targeted Parameter Perturbation',       drift: 34, quarantine: 0,  critical: 0,  tone: 'is-warn' },
    { meta: 'Containment engaged',         threat: 'High risk',     integ: 'Quarantine active',   danger: 'HIGH',    status: 'Quarantined', weight: '2.140', attack: 'Memory Integrity Violation',            drift: 22, quarantine: 34, critical: 0,  tone: 'is-danger' },
    { meta: 'Integrity breach isolated',   threat: 'Critical risk', integ: 'Isolation enforced',  danger: 'CRITICAL',status: 'Critical',    weight: '2.670', attack: 'Catastrophic Model Corruption',         drift: 12, quarantine: 26, critical: 44, tone: 'is-danger' }
  ];

  /* ============================================================
     CLOCK + UPTIME
     ============================================================ */
  var clockEl  = $('clock');
  var uptimeEl = $('uptime');
  var uptimeStart = Date.now();

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  function tickClock() {
    var d  = new Date();
    if (clockEl) clockEl.textContent = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    var up = Math.floor((Date.now() - uptimeStart) / 1000);
    var hh = Math.floor(up / 3600);
    var mm = Math.floor((up % 3600) / 60);
    var ss = up % 60;
    if (uptimeEl) uptimeEl.textContent = pad(hh) + ':' + pad(mm) + ':' + pad(ss);
  }
  tickClock();
  setInterval(tickClock, 1000);

  /* ============================================================
     TOAST
     ============================================================ */
  var toastEl    = $('toast');
  var toastTimer;

  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add('is-visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove('is-visible'); }, 3000);
  }

  /* ============================================================
     ELEMENT REFS
     ============================================================ */
  var els = {
    modelState:    $('model-state'),
    modelMeta:     $('model-meta'),
    variance:      $('variance-value'),
    threat:        $('threat-value'),
    threatMeta:    $('threat-meta'),
    integrity:     $('integrity-value'),
    integrityMeta: $('integrity-meta'),
    legNominal:    $('leg-nominal'),
    legDrift:      $('leg-drift'),
    legQuarantine: $('leg-quarantine'),
    legCritical:   $('leg-critical'),
    paramWeight:   $('param-weight'),
    paramStatus:   $('param-status'),
    paramDanger:   $('param-danger'),
    paramAttack:   $('param-attack'),
    pill:          $('live-pill'),
    pauseLabel:    $('pause-label'),
    pauseBtn:      $('pause-btn'),
    modelCard:     document.querySelector('.stat-card[data-tone="model"]'),
    integrityCard: document.querySelector('.stat-card[data-tone="integrity"]')
  };

  /* ============================================================
     TEXT / CLASS HELPERS
     ============================================================ */
  var _cache = {};
  function setText(el, key, value) {
    if (!el || _cache[key] === value) return;
    _cache[key] = value;
    el.textContent = value;
  }
  function setClass(el, cls, on) {
    if (el) el.classList.toggle(cls, !!on);
  }

  /* ============================================================
     APPLY LEVEL — update UI to a threat level index (0..4)
     ============================================================ */
  function applyLevel(index, announce) {
    index = Math.max(0, Math.min(LEVELS.length - 1, index));
    state.level = index;
    var conf = LEVELS[index];
    var copy = COPY[index];

    /* NOTE: Do NOT set state.*Target here — those are driven by real API
       values in fetchStatus(). We only update display labels and CSS classes. */

    setText(els.paramWeight,   'weight',   copy.weight);
    setText(els.paramStatus,   'status',   copy.status);
    setText(els.paramDanger,   'danger',   copy.danger);
    setText(els.paramAttack,   'attack',   copy.attack);
    setText(els.modelMeta,     'meta',     copy.meta);
    setText(els.threatMeta,    'threatMeta', copy.threat);
    setText(els.integrityMeta, 'integMeta',  copy.integ);

    setClass(els.modelCard,     'is-warn',   copy.tone === 'is-warn');
    setClass(els.modelCard,     'is-danger', copy.tone === 'is-danger');
    setClass(els.integrityCard, 'is-warn',   copy.tone === 'is-warn');
    setClass(els.integrityCard, 'is-danger', copy.tone === 'is-danger');

    document.querySelectorAll('[data-action]').forEach(function (btn) {
      var act = btn.getAttribute('data-action');
      var map = { baseline: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if (act in map) btn.classList.toggle('is-on', map[act] === index);
    });

    if (announce) {
      toast(index === 0
        ? 'Baseline restored · model clean'
        : 'THREAT: ' + conf.label + ' detected');
    }
  }

  /* ============================================================
     BACKEND SYNC — map API data → state.level + raw metrics
     ============================================================ */
  /* ============================================================
     BACKEND SYNC — map API data → state.level + raw metrics
     ============================================================ */
  function threatPctToLevel(pct) {
    /* Map real API threat_pct (0-99.9) to a LEVELS index (0-4). */
    if (pct >= 75) return 4;  // CRITICAL
    if (pct >= 45) return 3;  // HIGH
    if (pct >= 20) return 2;  // MEDIUM
    if (pct >= 3)  return 1;  // LOW
    return 0;                  // HEALTHY
  }

  function fetchStatus() {
    if (state.paused) return;
    fetch('/api/status', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) return;

        var threat_pct = typeof data.threat_pct === 'number' ? data.threat_pct : 0;
        var variance_pct = typeof data.variance_pct === 'number' ? data.variance_pct : 0;
        var integ = typeof data.integrity_score === 'number'
          ? data.integrity_score
          : Math.max(0, 100 - Math.min(100, threat_pct));
        var w   = typeof data.weight === 'number' ? data.weight.toFixed(3) : '1.500';
        var st  = data.status || 'HEALTHY';
        var atk = data.attack_name || 'Clean Baseline';
        var lvl = threatPctToLevel(threat_pct);

        /* Set real API targets FIRST — these drive the animated gauges */
        state.varianceTarget  = variance_pct;
        state.threatTarget    = threat_pct;
        state.integrityTarget = Math.max(0, 100 - Math.min(100, threat_pct));

        /* Drive chart chaos level — applyLevel does NOT touch *Target now */
        if (lvl !== state.level) {
          applyLevel(lvl, false);
        }

        /* Always override display labels with live API data */
        setText(els.paramWeight, 'weight', w);
        setText(els.paramStatus, 'status', st);
        setText(els.paramAttack, 'attack', atk || 'Clean Baseline');

        /* Override card tones based on live severity */
        var danger = data.danger_level || data.severity || 'NOMINAL';
        var isWarn   = danger === 'ELEVATED' || (threat_pct > 5  && threat_pct < 45);
        var isDanger = danger === 'CRITICAL'  || threat_pct >= 45;
        setClass(els.modelCard,     'is-warn',   isWarn   && !isDanger);
        setClass(els.modelCard,     'is-danger', isDanger);
        setClass(els.integrityCard, 'is-warn',   isWarn   && !isDanger);
        setClass(els.integrityCard, 'is-danger', isDanger);

        /* Update live status text */
        setText(els.modelState, 'state', LEVELS[state.level].label);

        /* Refresh observable data panels if visible */
        updateObservatory(data);
      })
      .catch(function () { /* server offline, keep animating */ });
  }

  /* ============================================================
     OBSERVATORY DATA PANEL
     ============================================================ */
  function updateObservatory(data) {
    var obsBody = $('obs-canary-body');
    if (!obsBody) return;

    var per = data.per_canary || [];
    var base = data.baseline_matrix || [];
    var obs  = data.observed_matrix || [];

    var rows = '';
    per.forEach(function (drift, i) {
      var pct = (drift * 100).toFixed(2);
      var expRow = base[i] ? (base[i][0] * 100).toFixed(1) + ' / ' + (base[i][1] * 100).toFixed(1) : '—';
      var actRow = obs[i]  ? (obs[i][0]  * 100).toFixed(1) + ' / ' + (obs[i][1]  * 100).toFixed(1) : '—';
      var cls = drift > 0.10 ? 'obs-crit' : drift > 0.02 ? 'obs-warn' : 'obs-ok';
      rows += '<tr class="' + cls + '">' +
        '<td>PROBE-' + (i + 1) + '</td>' +
        '<td>' + expRow + '</td>' +
        '<td>' + actRow + '</td>' +
        '<td>' + pct + '%</td>' +
        '</tr>';
    });
    obsBody.innerHTML = rows || '<tr><td colspan="4">No canary data yet.</td></tr>';

    var maxDrift = $('obs-max-drift');
    if (maxDrift) maxDrift.textContent = (data.max_drift !== undefined ? (data.max_drift * 100).toFixed(4) : '0.0000') + '%';
    var passedEl = $('obs-passed');
    if (passedEl) {
      passedEl.textContent = data.passed ? 'PASS' : 'FAIL';
      passedEl.className = 'obs-badge ' + (data.passed ? 'obs-ok' : 'obs-crit');
    }
  }

  /* ============================================================
     MODEL SAMPLE SCANNER (Layer 1 Static Bytecode Analysis)
     ============================================================ */
  var sampleSelect = $('bb-sample-select');
  var scanBtn = $('bb-scan-btn');
  var scanOutput = $('bb-scan-output');
  var verdictBadge = $('bb-verdict-badge');
  var scannerBadge = $('bb-scanner-badge');

  function loadSamples() {
    if (!sampleSelect) return;
    fetch('/api/samples', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.samples) return;
        var opts = data.samples.map(function (s) {
          return '<option value="' + esc(s) + '">' + esc(s) + '</option>';
        }).join('');
        sampleSelect.innerHTML = opts || '<option value="">No samples found</option>';
      })
      .catch(function () {});
  }

  function scanSelectedSample() {
    if (!sampleSelect) return;
    var file = sampleSelect.value;
    if (!file) {
      toast('Please select a model sample to inspect');
      return;
    }

    if (scannerBadge) {
      scannerBadge.textContent = 'SCANNING...';
      scannerBadge.className = 'obs-badge obs-ok';
    }
    toast('Scanning bytecode: ' + file + '...');

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file: file })
    })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (scannerBadge) {
          scannerBadge.textContent = 'READY';
          scannerBadge.className = 'obs-badge obs-ok';
        }

        if (res.error) {
          toast('Scan error: ' + res.error);
          if (scanOutput) scanOutput.innerHTML = '<p class="scan-finding-item is-high">Error: ' + esc(res.error) + '</p>';
          return;
        }

        var verdict = res.verdict || 'UNKNOWN';
        if (verdictBadge) {
          verdictBadge.textContent = verdict;
          verdictBadge.className = 'verdict-pill ' + (
            verdict === 'MALICIOUS' ? 'is-malicious' :
            verdict === 'SUSPICIOUS' ? 'is-warn' : 'is-safe'
          );
        }

        var findings = res.findings || [];
        var findingsHtml = findings.length
          ? '<ul class="scan-findings-list">' + findings.map(function (f) {
              var isHigh = f.severity === 'high';
              return '<li class="scan-finding-item ' + (isHigh ? 'is-high' : 'is-med') + '">' +
                '<span class="scan-opcode-tag">' + esc(f.opcode) + '</span>' +
                '<span>' + esc(f.detail) + '</span>' +
                '</li>';
            }).join('') + '</ul>'
          : '<p style="color:#70f2be;margin:4px 0;">✔ Clean model file. No malicious opcodes, shell execution, or unauthorized imports found.</p>';

        if (scanOutput) {
          scanOutput.innerHTML =
            '<div class="scan-metric-row">' +
              '<span class="scan-metric">File: <b>' + esc(file) + '</b></span>' +
              '<span class="scan-metric">Opcodes: <b>' + (res.opcodes_scanned || 0) + '</b></span>' +
              '<span class="scan-metric">Size: <b>' + (res.bytes_scanned || 0) + ' B</b></span>' +
              '<span class="scan-metric">Threats: <b style="color:' + (findings.length ? '#ff8595' : '#70f2be') + '">' + findings.length + '</b></span>' +
            '</div>' +
            findingsHtml;
        }

        toast(verdict === 'MALICIOUS' ? '🚨 THREAT DETECTED: ' + file : 'Scan complete · ' + verdict);
        fetchLogs();
      })
      .catch(function () {
        if (scannerBadge) scannerBadge.textContent = 'READY';
        toast('Scan request failed');
      });
  }

  if (scanBtn) scanBtn.addEventListener('click', scanSelectedSample);

  /* ============================================================
     BLACK BOX — event log & filtering
     ============================================================ */
  var logSearchInput = $('bb-log-search');
  var allLogs = [];

  function fetchLogs() {
    var logBody = $('bb-log-body');
    if (!logBody) return;
    fetch('/api/logs', { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.logs) return;
        allLogs = data.logs;
        renderLogs();
      })
      .catch(function () {});
  }

  function renderLogs() {
    var logBody = $('bb-log-body');
    if (!logBody) return;
    var q = (logSearchInput ? logSearchInput.value : '').toLowerCase().trim();
    var filtered = allLogs.filter(function (e) {
      if (!q) return true;
      var str = (e.timestamp + ' ' + e.event + ' ' + e.status + ' ' + e.severity + ' ' + e.details).toLowerCase();
      return str.indexOf(q) !== -1;
    });

    var rows = filtered.map(function (e) {
      var cls = e.severity === 'CRITICAL' || e.status === 'QUARANTINED' || e.status === 'MALICIOUS' ? 'log-crit'
              : e.severity === 'MEDIUM'   || e.status === 'SUSPICIOUS' ? 'log-warn'
              : 'log-ok';
      return '<tr class="' + cls + '">' +
        '<td class="log-ts">' + esc(e.timestamp || '') + '</td>' +
        '<td class="log-ev">' + esc(e.event) + '</td>' +
        '<td class="log-st">' + esc(e.status) + '</td>' +
        '<td class="log-sv">' + esc(e.severity) + '</td>' +
        '<td class="log-dt">' + esc(e.details) + '</td>' +
        '</tr>';
    }).join('');
    logBody.innerHTML = rows || '<tr><td colspan="5" class="obs-loading">No matching log entries found.</td></tr>';
  }

  if (logSearchInput) logSearchInput.addEventListener('input', renderLogs);
  var refreshLogsBtn = $('bb-refresh-btn');
  if (refreshLogsBtn) refreshLogsBtn.addEventListener('click', function () {
    fetchLogs();
    toast('Audit log refreshed');
  });

  function esc(s) {
    return String(s || '').replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function exportLogs() {
    fetch('/api/logs').then(function (r) { return r.json(); }).then(function (d) {
      var blob = new Blob([JSON.stringify(d.logs, null, 2)], { type: 'application/json' });
      var a    = document.createElement('a');
      a.href   = URL.createObjectURL(blob);
      a.download = 'primadoris-audit-' + new Date().toISOString().slice(0, 10) + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  var exportBtn = $('bb-export-btn');
  if (exportBtn) exportBtn.addEventListener('click', exportLogs);

  /* ============================================================
     PANEL NAVIGATION — proper show/hide view switching
     ============================================================ */
  function showPanel(view) {
    document.querySelectorAll('.view-panel').forEach(function (p) {
      p.style.display = 'none';
    });
    var panel = document.querySelector('.view-panel[data-panel="' + view + '"]');
    if (panel) panel.style.display = '';

    /* When returning to THE ABYSS, invalidate chart sizing */
    if (view === 'THE ABYSS') {
      if (window.PrimadorisCharts) window.PrimadorisCharts.invalidate();
    }

    /* Trigger log and sample load when entering BLACK BOX */
    if (view === 'BLACK BOX') {
      loadSamples();
      fetchLogs();
    }
  }

  document.querySelectorAll('.nav-item').forEach(function (item) {
    item.addEventListener('click', function () {
      document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('is-active'); });
      item.classList.add('is-active');
      var view = item.getAttribute('data-view') || 'THE ABYSS';
      showPanel(view);

      if (view === 'THE ABYSS')        toast('THE ABYSS · live neural overview');
      else if (view === 'THREAT LAB')  toast('THREAT LAB · launch an attack scenario');
      else if (view === 'OBSERVATORY') toast('OBSERVATORY · per-probe drift analysis');
      else                             toast('BLACK BOX · full audit event log');
    });
  });

  /* Sync pause-btn-2 in THREAT LAB with main pause state */
  function syncPauseLabel() {
    var lbl2 = $('pause-label-2');
    if (lbl2) lbl2.textContent = state.paused ? 'Resume Monitoring' : 'Pause Monitoring';
  }

  /* ============================================================
     QUICK CONTROLS (attack + reset)
     ============================================================ */
  document.querySelectorAll('[data-action]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var act = btn.getAttribute('data-action');
      var map = { baseline: 0, low: 1, medium: 2, high: 3, critical: 4 };

      if (act === 'pause') {
        state.paused = !state.paused;
        if (els.pauseLabel) els.pauseLabel.textContent = state.paused ? 'Resume Monitoring' : 'Pause Monitoring';
        if (els.pill) {
          els.pill.classList.toggle('is-paused', state.paused);
          els.pill.innerHTML = state.paused ? '<i></i>PAUSED' : '<i></i>LIVE';
        }
        if (els.pauseBtn) els.pauseBtn.classList.toggle('is-on', state.paused);
        toast(state.paused ? 'Monitoring paused' : 'Monitoring resumed');
        return;
      }

      if (act === 'baseline') {
        toast('Restoring clean PyTorch baseline...');
        fetch('/api/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            applyLevel(0, false);
            toast('Baseline restored · ' + (d.message || 'model clean'));
            setTimeout(fetchStatus, 300);
          })
          .catch(function () { applyLevel(0, true); });
        return;
      }

      if (act in map) {
        var lvlIdx = map[act];
        var lvlName = act.toUpperCase();
        toast('Launching ' + lvlName + ' attack on PyTorch model...');
        fetch('/api/attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ level: lvlName })
        })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (d && d.success) {
              toast(d.attack_name + ' · drift +' + (d.variance_pct ? d.variance_pct.toFixed(2) : '0') + '%');
              setTimeout(fetchStatus, 300);
            }
          })
          .catch(function () { applyLevel(lvlIdx, true); });
      }
    });
  });

  /* ============================================================
     ANIMATION SYNC LOOP — feeds canvas instruments
     ============================================================ */
  var frameCount = 0;

  function syncAnimations() {
    frameCount++;
    if (frameCount % 3 !== 0) { requestAnimationFrame(syncAnimations); return; }

    var conf = LEVELS[state.level];
    var copy = COPY[state.level];

    setText(els.modelState, 'state', conf.label);
    setText(els.variance,   'variance',  state.variance.toFixed(2));
    setText(els.threat,     'threat',    state.threat.toFixed(1));
    setText(els.integrity,  'integrity', String(Math.round(state.integrity)));

    var nominal    = Math.round(state.integrity);
    var drift      = Math.round(copy.drift      * (state.integrity / Math.max(1, conf.integrity)));
    var quarantine = Math.round(copy.quarantine * (state.integrity / Math.max(1, conf.integrity)));
    var critical   = Math.max(0, Math.round(100 - nominal - drift - quarantine));

    setText(els.legNominal,    'legNominal',    nominal    + '%');
    setText(els.legDrift,      'legDrift',      drift      + '%');
    setText(els.legQuarantine, 'legQuarantine', quarantine + '%');
    setText(els.legCritical,   'legCritical',   critical   + '%');

    requestAnimationFrame(syncAnimations);
  }

  /* ============================================================
     BOOT
     ============================================================ */
  applyLevel(0, false);
  setText(els.modelState,  'state',     LEVELS[0].label);
  setText(els.variance,    'variance',  '0.00');
  setText(els.threat,      'threat',    '0.0');
  setText(els.integrity,   'integrity', '100');
  setText(els.legNominal,  'legNominal','100%');

  showPanel('THE ABYSS');
  requestAnimationFrame(syncAnimations);
  loadSamples();
  fetchLogs();
  setInterval(fetchStatus, 2500);
  setInterval(fetchLogs, 8000);
  fetchStatus();
})();
