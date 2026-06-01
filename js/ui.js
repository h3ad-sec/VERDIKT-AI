
let currentVerdictFilter = 'all';
let currentTypeFilter    = 'all';
let currentSearch        = '';
let _currentModalEntry = null;

const TYPE_BADGES = {
  ip:          '<span class="type-badge type-ip">IPv4</span>',
  ipv6:        '<span class="type-badge type-ipv6">IPv6</span>',
  domain:      '<span class="type-badge type-domain">Domain</span>',
  url:         '<span class="type-badge type-url">URL</span>',
  hash_md5:    '<span class="type-badge type-hash">MD5</span>',
  hash_sha1:   '<span class="type-badge type-hash">SHA-1</span>',
  hash_sha256: '<span class="type-badge type-hash">SHA-256</span>',
  hash_sha512: '<span class="type-badge type-hash">SHA-512</span>',
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escapeAttr(s) { return escapeHtml(s); }
function truncate(s, n) { s = String(s||''); return s.length > n ? s.slice(0,n)+'…' : s; }

function showToast(msg, type = 'info') {
  let t = document.getElementById('xv-toast');
  if (!t) {
    t = document.createElement('div'); t.id = 'xv-toast';
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;padding:11px 18px;font-family:var(--mono);font-size:13px;border:1px solid;border-radius:4px;pointer-events:none;transition:opacity .3s;max-width:340px;';
    document.body.appendChild(t);
  }
  const styles = {
    success: 'background:rgba(0,255,159,.08);border-color:rgba(0,255,159,.4);color:var(--accent)',
    error:   'background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.4);color:var(--red)',
    warning: 'background:rgba(255,214,10,.08);border-color:rgba(255,214,10,.4);color:var(--yellow)',
    info:    'background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.4);color:var(--accent2)',
  };
  t.style.cssText += styles[type] || styles.info;
  t.textContent = msg; t.style.opacity = '1';
  clearTimeout(t._tid);
  t._tid = setTimeout(() => { t.style.opacity = '0'; }, 3200);
}

function copyToClipboard(val) {
  navigator.clipboard.writeText(val).then(() => showToast('Copied!', 'success'));
}

/* ── Result table ────────────────────────────────────────────────────────── */
function renderResultRows(results) {
  document.getElementById('results-body').innerHTML = results.map((e, i) => buildRow(e, i)).join('');
  applyFilters();
}

function buildRow(entry, i) {
  const { ioc, verdict, action, score, vtPts, abPts, mbPts, otxPts, tfPts, usPts, uhPts, haPts, confidence, flags, done } = entry;
  const typeBadge    = TYPE_BADGES[ioc.type] || `<span class="type-badge">${escapeHtml(ioc.label)}</span>`;
  const privateBadge = ioc.isPrivate ? '<div class="ioc-private-badge">PRIVATE</div>' : '';
  const displayVal   = ioc.type === 'url' || ioc.type.startsWith('hash_') ? truncate(ioc.value, 48) : ioc.value;
  const isHash = ioc.type.startsWith('hash_');
  const isIP   = ioc.type === 'ip' || ioc.type === 'ipv6';
  const isURL  = ioc.type === 'url';
  const vtMax  = isIP ? 30 : isHash ? 30 : 50;

  return `<tr data-row="${i}" data-verdict="${verdict||'pending'}" data-action="${action||''}" data-type="${escapeAttr(ioc.type)}" data-ioc="${escapeAttr(ioc.value)}">
    <td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val" title="${escapeAttr(ioc.value)}">${escapeHtml(displayVal)}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘</button>
      </div>
      ${privateBadge}
    </td>
    <td>${typeBadge}</td>
    <td id="v-${i}">${buildVerdictCell(verdict, score, confidence, done)}</td>
    <td id="vt-${i}">${buildSourceScoreCell('vt', vtPts, entry.vt, done, vtMax)}</td>
    <td id="ab-${i}">${isHash ? buildSourceScoreCell('mb', mbPts, entry.mb, done, 15) : isIP ? buildSourceScoreCell('ab', abPts, entry.ab, done, 40) : buildSourceScoreCell('us', usPts, entry.urlscan, done, 20)}</td>
    <td id="otx-${i}">${buildSourceScoreCell('otx', otxPts, entry.otx, done, 10)}</td>
    <td id="ha-${i}">${isHash ? buildSourceScoreCell('ha', haPts, entry.ha, done, 30) : '<span style="color:var(--muted);font-size:11px">-</span>'}</td>
    <td id="tf-${i}">${isURL ? buildSourceScoreCell('uh', uhPts, entry.urlhaus, done, 20) : buildSourceScoreCell('tf', tfPts, entry.threatfox, done, isHash?15:20)}</td>
    <td id="fl-${i}">${buildFlagsCell(flags, done)}</td>
    <td id="copy-${i}">${done ? `<button class="btn-ii-copy" onclick="copyStdRow(${i})" title="Copy as key-value">⎘</button>` : ''}</td>
    <td id="det-${i}">${done ? `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>` : '<span class="src-loading">…</span>'}</td>
    <td id="ai-btn-${i}">${done ? `<button class="btn-ai" onclick="toggleAIPanel(${i})" title="AI analysis">AI</button>` : ''}</td>
  </tr>`;
}

function buildVerdictCell(verdict, score, confidence, done) {
  if (!done) return `<div class="verdict-pending-cell"><div class="vc-spinner"></div><span>Scanning…</span></div>`;
  const vMap = {
    malicious:  { icon:'🔴', label:'MALICIOUS',  cls:'verdict-malicious' },
    suspicious: { icon:'🟡', label:'SUSPICIOUS', cls:'verdict-suspicious' },
    benign:     { icon:'🟢', label:'BENIGN',     cls:'verdict-benign' },
    unknown:    { icon:'⚪', label:'UNKNOWN',    cls:'verdict-unknown' },
  };
  const v = vMap[verdict] || vMap.unknown;
  const confColor = { high:'var(--accent)', medium:'var(--yellow)', low:'var(--muted)', informational:'var(--accent2)' }[confidence] || 'var(--muted)';
  return `<div class="verdict-cell">
    <span class="verdict-badge ${v.cls}">${v.icon} ${v.label}</span>
    <div class="vc-meta">
      <span class="vc-score">${score!=null?score:'-'}<span class="vc-score-unit">/100</span></span>
      <span class="vc-sep">·</span>
      <span class="vc-conf" style="color:${confColor}">${(confidence||'-').toUpperCase()}</span>
    </div>
  </div>`;
}

function buildSourceScoreCell(src, pts, data, done, maxPts) {
  if (!done) return '<span class="src-loading">…</span>';
  const colors = { vt:'var(--vt)', ab:'var(--ab)', otx:'var(--otx)', mb:'var(--mb)', tf:'var(--tf)', us:'var(--us)', uh:'var(--uh)', ha:'var(--ha)' };
  const col = colors[src] || 'var(--muted)';
  if (!data || data.skipped) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px">-</span></div>`;
  if (data.error) return `<div class="src-score-cell"><span style="color:var(--muted);font-size:11px" title="${escapeAttr(data.error)}">ERR</span></div>`;
  const pct = (pts!=null&&maxPts>0) ? Math.min(100,Math.round((pts/maxPts)*100)) : 0;
  let label = '';
  if (src==='vt')  label = data.total>0 ? `${data.malicious}/${data.total}` : 'N/A';
  if (src==='ab')  label = `${data.score||0}%`;
  if (src==='otx') label = `${data.pulseCount||0} pulse${(data.pulseCount||0)!==1?'s':''}`;
  if (src==='mb')  label = data.notFound ? 'Clean' : `${data.count||0} sample${(data.count||0)!==1?'s':''}`;
  if (src==='tf')  label = data.notFound ? 'No C2' : `${data.iocCount||0} C2${data.maxConfidence?` ${data.maxConfidence}%`:''}`;
  if (src==='us')  label = data.notFound ? 'No scans' : `${data.maliciousCount||0}/${data.total||0} mal`;
  if (src==='uh')  label = data.notFound ? 'Not found' : `${data.urlsCount||0} URL${(data.urlsCount||0)!==1?'s':''}`;
  if (src==='ha')  label = data.notFound ? 'No hits' : (data.families?.[0] ? truncate(data.families[0],12) : `${data.count||0} hit${(data.count||0)!==1?'s':''}`);
  return `<div class="src-score-cell">
    <div class="src-val" style="color:${col}">${escapeHtml(label)}</div>
    <div class="src-bar"><div class="src-bar-fill" style="width:${pct}%;background:${col}"></div></div>
  </div>`;
}

function buildFlagsCell(flags, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!flags?.length) return '<span style="color:var(--muted);font-size:11px">-</span>';
  const flagColors = { 'TF:C2':'var(--tf)', 'UH:URLS':'var(--uh)', 'MB:HIT':'var(--mb)' };
  return flags.map(f => {
    const col = flagColors[f] || (f.startsWith('US:') ? 'var(--us)' : 'var(--muted)');
    return `<span class="flag-chip" style="border-color:${col};color:${col}">${escapeHtml(f)}</span>`;
  }).join('');
}

function buildIntelCell(src, data, done) {
  if (!done) return '<span class="src-loading">…</span>';
  if (!data || data.skipped) return '<span style="color:var(--muted);font-size:11px">-</span>';
  if (data.error) return `<span style="color:var(--muted);font-size:11px" title="${escapeAttr(data.error)}">ERR</span>`;
  switch (src) {
    case 'vt': {
      if (!data.total) return '<span class="ipi-nf">N/A</span>';
      const col = data.malicious > 0 ? 'var(--red)' : 'var(--accent)';
      return `<span style="color:${col}">${data.malicious}/${data.total}</span>`;
    }
    case 'ab':
      return `<span style="font-weight:600;color:${data.score >= 75 ? 'var(--red)' : data.score >= 25 ? 'var(--yellow)' : 'var(--accent)'}">${data.score}%</span>`;
    case 'otx':
      return `<span style="color:${data.pulseCount > 0 ? 'var(--yellow)' : 'var(--muted)'}">${data.pulseCount}</span>`;
    case 'mb':
      return data.notFound
        ? `<span style="color:var(--accent)">clean</span>`
        : `<span style="color:var(--red)">${data.count} samp</span>`;
    case 'tf':
      return data.notFound
        ? `<span style="color:var(--accent)">none</span>`
        : `<span style="color:var(--red)">${data.iocCount}</span>`;
    case 'us':
      if (data.notFound || !data.total) return '<span class="ipi-nf">none</span>';
      return `<span style="color:${data.maliciousCount > 0 ? 'var(--red)' : 'var(--accent)'}">${data.maliciousCount}/${data.total}</span>`;
    case 'uh':
      return data.notFound
        ? `<span style="color:var(--accent)">none</span>`
        : `<span style="color:var(--red)">${data.urlsCount}</span>`;
    case 'ha':
      if (data.notFound || !data.count) return `<span style="color:var(--accent)">none</span>`;
      return `<span style="color:${data.verdict === 'malicious' ? 'var(--red)' : 'var(--yellow)'}">HA:${data.count}</span>`;
    default:
      return '<span class="ipi-nf">-</span>';
  }
}

function copyStdRow(i) {
  const entry = scanResults[i];
  if (!entry || !entry.done) { showToast('Row not ready', 'warning'); return; }
  const { ioc, vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha } = entry;
  const parts = [`IOC: ${ioc.value} | Type: ${ioc.label}`];
  if (vt  && !vt.skipped  && !vt.error)  parts.push(`VT: ${vt.malicious}/${vt.total} engines`);
  if (ab  && !ab.skipped  && !ab.error)  parts.push(`AbuseIPDB: ${ab.score}%`);
  if (urlscan && !urlscan.skipped && !urlscan.error && !urlscan.notFound) parts.push(`URLScan: ${urlscan.maliciousCount}/${urlscan.total} malicious`);
  if (mb  && !mb.skipped  && !mb.error  && !mb.notFound)  parts.push(`MalwareBazaar: ${mb.count} samples`);
  if (otx && !otx.skipped && !otx.error) parts.push(`OTX: ${otx.pulseCount} pulses`);
  if (threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound) parts.push(`ThreatFox: ${threatfox.iocCount} C2 IOCs`);
  if (urlhaus && !urlhaus.skipped && !urlhaus.error && !urlhaus.notFound) parts.push(`URLhaus: ${urlhaus.urlsCount} URLs`);
  if (ha  && !ha.skipped  && !ha.error  && !ha.notFound)  parts.push(`HybridAnalysis: ${ha.count} hits (${ha.verdict || 'unknown'})`);
  iiClipboard(parts.join(' | '), 'Copied to clipboard');
}

function updateRow(i, entry) {
  const { verdict, action, score, vtPts, abPts, mbPts, otxPts, tfPts, usPts, uhPts, haPts, confidence, flags, vt, ab, mb, otx, ha, threatfox, urlhaus, urlscan } = entry;
  const t      = entry.ioc.type;
  const isHash = t.startsWith('hash_');
  const isIP   = t === 'ip' || t === 'ipv6';
  const isURL  = t === 'url';
  const vtMax  = isIP ? 30 : isHash ? 30 : 50;
  const g   = id => document.getElementById(`${id}-${i}`);
  const set = (id, html) => { const el = g(id); if (el) el.innerHTML = html; };

  set('v',      buildVerdictCell(verdict, score, confidence, true));
  set('vt',     buildSourceScoreCell('vt', vtPts, vt, true, vtMax));
  set('ab',     isHash ? buildSourceScoreCell('mb', mbPts, mb, true, 15) : isIP ? buildSourceScoreCell('ab', abPts, ab, true, 40) : buildSourceScoreCell('us', usPts, urlscan, true, 20));
  set('otx',    buildSourceScoreCell('otx', otxPts, otx, true, 10));
  set('ha',     isHash ? buildSourceScoreCell('ha', haPts, ha, true, 30) : '<span style="color:var(--muted);font-size:11px">-</span>');
  set('tf',     isURL ? buildSourceScoreCell('uh', uhPts, urlhaus, true, 20) : buildSourceScoreCell('tf', tfPts, threatfox, true, isHash?15:20));
  set('fl',     buildFlagsCell(flags, true));
  set('copy',   `<button class="btn-ii-copy" onclick="copyStdRow(${i})" title="Copy as key-value">⎘</button>`);
  set('det',    `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>`);
  set('ai-btn', `<button class="btn-ai" onclick="toggleAIPanel(${i})" title="AI analysis">AI</button>`);

  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (row) { row.dataset.verdict = verdict||'unknown'; row.dataset.action = action||''; }
  applyFilters();
}

function updateRowLoading(i) {
  ['v','vt','ab','otx','ha','tf','fl','ai-btn'].forEach(id => {
    const el = document.getElementById(`${id}-${i}`);
    if (el) el.innerHTML = '<div class="verdict-pending-cell"><div class="vc-spinner"></div></div>';
  });
}

/* ── Summary strip ────────────────────────────────────────────────────────── */
function renderSummary(results) {
  const done = results.filter(r => r.done);
  const cnt  = { malicious:0, suspicious:0, benign:0, unknown:0 };
  const scores = [];
  done.forEach(r => { if (cnt[r.verdict]!==undefined) cnt[r.verdict]++; if (r.score!=null) scores.push(r.score); });
  const avg = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : null;
  document.getElementById('summary-strip').innerHTML = `
    <div class="summary-card sc-total"><span class="sc-icon">📋</span><div><div class="summary-num">${results.length}</div><div class="summary-lbl">TOTAL</div></div></div>
    <div class="summary-card"><div><div class="summary-num" style="color:var(--red)">${cnt.malicious}</div><div class="summary-lbl">MALICIOUS</div></div></div>
    <div class="summary-card"><div><div class="summary-num" style="color:var(--yellow)">${cnt.suspicious}</div><div class="summary-lbl">SUSPICIOUS</div></div></div>
    <div class="summary-card"><div><div class="summary-num" style="color:var(--accent)">${cnt.benign}</div><div class="summary-lbl">BENIGN</div></div></div>
    <div class="summary-card"><div><div class="summary-num" style="color:var(--muted)">${cnt.unknown}</div><div class="summary-lbl">UNKNOWN</div></div></div>
    ${avg!=null?`<div class="summary-card"><div><div class="summary-num" style="color:var(--accent2)">${avg}</div><div class="summary-lbl">AVG RISK</div></div></div>`:''}
  `;
}

/* ── Filters ─────────────────────────────────────────────────────────────── */
function filterResults(v, btn) {
  currentVerdictFilter = v;
  document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function filterByType(t, btn) {
  currentTypeFilter = t;
  document.querySelectorAll('.type-filter[data-tfilter]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function searchResults(val) { currentSearch = val.toLowerCase().trim(); applyFilters(); }

function applyFilters() {
  document.querySelectorAll('#results-body tr[data-row]').forEach(row => {
    const tp  = row.dataset.type || '';
    const vrd = row.dataset.verdict || '';
    const ioc = (row.dataset.ioc || '').toLowerCase();
    const matchV = currentVerdictFilter === 'all' || vrd === currentVerdictFilter;
    const matchT = currentTypeFilter === 'all' || tp === currentTypeFilter
                   || (currentTypeFilter === 'hash' && tp.startsWith('hash_'));
    const matchS = !currentSearch || ioc.includes(currentSearch);
    const hide = !(matchV && matchT && matchS);
    row.classList.toggle('hidden', hide);
    const panelRow = document.getElementById(`ai-panel-row-${row.dataset.row}`);
    if (panelRow && hide) panelRow.style.display = 'none';
  });
}

/* ── Status dots ─────────────────────────────────────────────────────────── */
function setServerStatusDots(status) {
  const map = {
    'vt-status': status.vt, 'ab-status': status.abuseipdb, 'otx-status': status.otx,
    'us-status': status.urlscan, 'tf-status': status.threatfox, 'uh-status': true,
    'mb-status': status.abusech, 'ha-status': status.hybridanalysis,
  };
  for (const [id, active] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (!el) continue;
    const dot = el.querySelector('.hstatus-dot');
    if (dot) { dot.className = active ? 'hstatus-dot on' : 'hstatus-dot off'; }
  }
}

/* ── Modal ────────────────────────────────────────────────────────────────── */
function openModal(i) {
  const entry = scanResults[i];
  if (!entry) return;
  _currentModalEntry = entry;
  const isIP = entry.ioc.type === 'ip' || entry.ioc.type === 'ipv6';
  document.getElementById('modal-title').innerHTML = buildModalTitle(entry);
  document.getElementById('modal-header-actions').innerHTML = isIP
    ? `<button class="iph-copy-btn" onclick="copyIPHighlights()">COPY</button>` : '';
  document.getElementById('modal-body').innerHTML  = buildModalContent(entry);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() { document.getElementById('modal-overlay')?.classList.remove('open'); }

function buildIPHighlightsCard(entry) {
  const { vt, ab, otx } = entry;
  const vtOk  = vt  && !vt.skipped  && !vt.error;
  const abOk  = ab  && !ab.skipped  && !ab.error;
  const otxOk = otx && !otx.skipped && !otx.error;

  const vtContent = vtOk ? `
    <div class="modal-kv-grid">
      ${kv('IP', vt.ip)}
      ${kv('ASN', vt.asn != null ? 'AS' + vt.asn : null)}
      ${kv('AS Owner', vt.as_owner)}
      ${kv('Country', vt.country)}
      ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : vt.reputation > 0 ? 'var(--accent)' : null)}
      ${kv('Detections', `${vt.malicious||0}/${vt.total||0} engines`, vt.malicious > 0 ? 'var(--red)' : 'var(--accent)')}
      ${kv('Network', vt.network)}
      ${kv('JARM', vt.jarm ? truncate(vt.jarm, 32) : null)}
      ${vt.tags?.length ? kv('Tags', vt.tags.join(', ')) : ''}
    </div>
    ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label" style="margin-top:8px">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Self-signed', vt.cert_self_signed)}
        ${kv('Valid Until', vt.cert_valid_until)}
        ${kv('SHA-256', vt.cert_thumbprint ? truncate(vt.cert_thumbprint, 32) : null)}
      </div>` : ''}` : '<div class="intel-na">-</div>';

  const abContent = abOk ? `
    <div class="modal-kv-grid">
      ${kv('IP Address', ab.ipAddress)}
      ${kv('IP Version', ab.ipVersion != null ? 'IPv' + ab.ipVersion : null)}
      ${kv('Is Public', ab.isPublic)}
      ${kv('Whitelisted', ab.isWhitelisted)}
      ${kv('Abuse Score', `${ab.score||0}%`, ab.score >= 75 ? 'var(--red)' : ab.score >= 25 ? 'var(--yellow)' : 'var(--accent)')}
      ${kv('Usage Type', ab.usageType)}
      ${kv('ISP', ab.isp)}
      ${kv('Domain', ab.domain)}
      ${kv('Hostnames', ab.hostnames?.length ? ab.hostnames.slice(0, 4).join(', ') : null)}
      ${kv('Is Tor', ab.isTor)}
    </div>` : '<div class="intel-na">-</div>';

  const otxContent = otxOk ? `
    <div class="modal-kv-grid">
      ${kv('Pulse Count', String(otx.pulseCount), otx.pulseCount >= 5 ? 'var(--red)' : otx.pulseCount >= 1 ? 'var(--yellow)' : 'var(--accent)')}
      ${kv('Subscribers', String(otx.subscriberCount || 0))}
      ${kv('Indicator Count', String(otx.indicatorCount || 0))}
      ${kv('Validation', otx.validation)}
      ${kv('Pulse Sources', otx.pulseSources?.length ? otx.pulseSources.join(', ') : null)}
      ${kv('Recent Pulse', otx.recentPulse ? truncate(otx.recentPulse, 44) : null)}
    </div>` : '<div class="intel-na">-</div>';

  return `<div class="ip-highlight-card">
    <div class="iph-header">
      <span class="iph-title">IP INTELLIGENCE HIGHLIGHTS</span>
      <button class="iph-copy-btn" onclick="copyIPHighlights()">COPY</button>
    </div>
    <div class="iph-grid">
      <div class="iph-col">
        <div class="iph-col-title" style="color:var(--vt)">VIRUSTOTAL</div>
        ${vtContent}
      </div>
      <div class="iph-col">
        <div class="iph-col-title" style="color:var(--ab)">ABUSEIPDB</div>
        ${abContent}
      </div>
      <div class="iph-col">
        <div class="iph-col-title" style="color:var(--otx)">OTX SIGNAL QUALITY</div>
        ${otxContent}
      </div>
    </div>
  </div>`;
}

window.copyIPHighlights = function() {
  const e = _currentModalEntry;
  if (!e) return;
  const { vt, ab, otx, ioc } = e;
  const f = v => (v == null || v === '') ? '-' : String(v);
  const lines = [
    `IOC: ${ioc.value}`,
    '',
    '[VIRUSTOTAL]',
  ];
  if (vt && !vt.skipped && !vt.error) {
    lines.push(
      `IP: ${f(vt.ip)}`,
      `ASN: ${vt.asn != null ? 'AS' + vt.asn : '-'}`,
      `AS Owner: ${f(vt.as_owner)}`,
      `Country: ${f(vt.country)}`,
      `Reputation: ${f(vt.reputation)}`,
      `Detections: ${vt.malicious||0}/${vt.total||0} engines (${vt.suspicious||0} suspicious)`,
      `Network: ${f(vt.network)}`,
      `JARM: ${f(vt.jarm)}`,
      `Tags: ${vt.tags?.length ? vt.tags.join(', ') : '-'}`,
    );
    if (vt.cert_subject_cn || vt.cert_issuer_cn) {
      lines.push(
        'TLS Certificate:',
        `  Subject CN: ${f(vt.cert_subject_cn)}`,
        `  Issuer CN: ${f(vt.cert_issuer_cn)}`,
        `  Self-signed: ${f(vt.cert_self_signed)}`,
        `  Valid Until: ${f(vt.cert_valid_until)}`,
        `  SHA-256: ${f(vt.cert_thumbprint)}`,
      );
    }
  } else lines.push(vt?.error ? `Error: ${vt.error}` : '-');

  lines.push('', '[ABUSEIPDB]');
  if (ab && !ab.skipped && !ab.error) {
    lines.push(
      `IP Address: ${f(ab.ipAddress)}`,
      `IP Version: ${ab.ipVersion != null ? 'IPv' + ab.ipVersion : '-'}`,
      `Is Public: ${f(ab.isPublic)}`,
      `Whitelisted: ${f(ab.isWhitelisted)}`,
      `Abuse Score: ${ab.score||0}%`,
      `Usage Type: ${f(ab.usageType)}`,
      `ISP: ${f(ab.isp)}`,
      `Domain: ${f(ab.domain)}`,
      `Hostnames: ${ab.hostnames?.length ? ab.hostnames.join(', ') : '-'}`,
      `Is Tor: ${f(ab.isTor)}`,
    );
  } else lines.push(ab?.error ? `Error: ${ab.error}` : '-');

  lines.push('', '[OTX SIGNAL QUALITY]');
  if (otx && !otx.skipped && !otx.error) {
    lines.push(
      `Pulse Count: ${otx.pulseCount||0}`,
      `Subscriber Count: ${otx.subscriberCount||0}`,
      `Indicator Count: ${otx.indicatorCount||0}`,
      `Validation: ${f(otx.validation)}`,
      `Pulse Sources: ${otx.pulseSources?.length ? otx.pulseSources.join(', ') : '-'}`,
      `Recent Pulse: ${f(otx.recentPulse)}`,
    );
  } else lines.push(otx?.error ? `Error: ${otx.error}` : '-');

  copyToClipboard(lines.join('\n'));
};

function buildModalTitle(entry) {
  const displayVal = entry.ioc.type === 'url' || entry.ioc.type.startsWith('hash_')
    ? truncate(entry.ioc.value, 60) : entry.ioc.value;
  return `<span title="${escapeAttr(entry.ioc.value)}">${escapeHtml(displayVal)}</span>
    <span style="color:var(--muted);font-size:11px;margin-left:12px">${escapeHtml(entry.ioc.label)}</span>`;
}

function buildModalContent(entry) {
  const { ioc, vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha } = entry;
  const iocType   = ioc.type;
  const iocIsIP   = iocType === 'ip' || iocType === 'ipv6';
  const iocIsHash = iocType.startsWith('hash_');
  const iocIsDom  = iocType === 'domain';
  const parts     = [];

  if (iocIsIP) {
    parts.push(buildIPHighlightsCard(entry));
    parts.push(`<div class="modal-intel-grid">
      ${buildVTBlock(vt, iocType)}
      ${buildAbuseIPDBBlock(ab, iocType)}
      ${buildOTXBlock(otx)}
      ${buildMainCard('THREATFOX', 'var(--tf)', buildThreatFoxContent(threatfox), threatfox?.link)}
    </div>`);
  } else if (iocIsHash) {
    parts.push(`<div class="modal-intel-grid">
      ${buildVTBlock(vt, iocType)}
      ${buildMBIntelBlock(mb)}
      ${buildOTXBlock(otx)}
      ${buildMainCard('THREATFOX',      'var(--tf)', buildThreatFoxContent(threatfox), threatfox?.link)}
      ${buildMainCard('HYBRIDANALYSIS', 'var(--ha)', buildHAContent(ha),               ha?.link)}
    </div>`);
  } else if (iocIsDom) {
    parts.push(`<div class="modal-intel-grid">
      ${buildVTBlock(vt, iocType)}
      ${buildOTXBlock(otx)}
      ${buildMainCard('URLSCAN',   'var(--us)', buildURLScanContent(urlscan),     urlscan?.link)}
      ${buildMainCard('THREATFOX', 'var(--tf)', buildThreatFoxContent(threatfox), threatfox?.link)}
    </div>`);
  } else {
    parts.push(`<div class="modal-intel-grid">
      ${buildVTBlock(vt, iocType)}
      ${buildOTXBlock(otx)}
      ${buildMainCard('URLSCAN',  'var(--us)', buildURLScanContent(urlscan),  urlscan?.link)}
      ${buildMainCard('URLHAUS',  'var(--uh)', buildURLhausContent(urlhaus),  urlhaus?.link)}
    </div>`);
  }

  return parts.join('');
}

function kv(k, v, col) {
  if (v == null || v === '' || v === 'null') return '';
  const val = typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v);
  const colorClass = col ? ` style="color:${col}"` : '';
  return `<div class="modal-k">${escapeHtml(k)}</div><div class="modal-v"${colorClass}>${escapeHtml(val)}</div>`;
}

function buildVTBlock(vt, iocType) {
  if (!vt || vt.skipped || vt.error) {
    const msg = vt?.error || vt?.reason || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  const scoreColor = vt.malicious > 0 ? 'var(--red)' : vt.suspicious > 0 ? 'var(--yellow)' : 'var(--accent)';
  const lastStats  = `${vt.malicious} mal · ${vt.suspicious} sus · ${vt.harmless} harm · ${vt.undetected} undet · ${vt.total} total`;
  const linkHtml   = vt.link ? ` <a href="${escapeAttr(vt.link)}" target="_blank" class="modal-link">↗</a>` : '';

  if (iocType === 'ip' || iocType === 'ipv6') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('IP', vt.ip)}
        ${kv('ASN', vt.asn != null ? `AS${vt.asn}` : null)}
        ${kv('AS Owner', vt.as_owner)}
        ${kv('Country', vt.country)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : vt.reputation > 0 ? 'var(--accent)' : null)}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Network', vt.network)}
        ${kv('JARM', vt.jarm ? truncate(vt.jarm, 32) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Self-signed', vt.cert_self_signed)}
        ${kv('Valid Until', vt.cert_valid_until)}
        ${kv('SHA-256', vt.cert_thumbprint ? truncate(vt.cert_thumbprint, 40) : null)}
      </div>` : ''}
    </div>`;
  }

  if (iocType === 'domain') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Domain', vt.domain)}
        ${kv('Registrar', vt.registrar)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Valid Until', vt.cert_valid_until)}
      </div>` : ''}
    </div>`;
  }

  if (iocType === 'url') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Title', vt.title ? truncate(vt.title, 48) : null)}
        ${kv('Final URL', vt.finalUrl ? truncate(vt.finalUrl, 48) : null)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  if (iocType.startsWith('hash_')) {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('File Name', vt.name)}
        ${kv('File Type', vt.fileType)}
        ${kv('Size', vt.size)}
        ${kv('Signature', vt.signatureInfo)}
        ${kv('First Seen', vt.firstSeen)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('MD5', vt.md5 ? truncate(vt.md5, 40) : null)}
        ${kv('SHA-1', vt.sha1 ? truncate(vt.sha1, 40) : null)}
        ${kv('SHA-256', vt.sha256 ? truncate(vt.sha256, 44) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
    <div class="modal-kv-grid">${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}</div>
  </div>`;
}

function buildAbuseIPDBBlock(ab, iocType) {
  if (!ab || ab.error) {
    const msg = ab?.error || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  if (ab.skipped) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na" style="color:var(--muted)">${escapeHtml(ab.reason || 'IP only')}</div></div>`;
  }
  const scoreCol = ab.score >= 75 ? 'var(--red)' : ab.score >= 25 ? 'var(--yellow)' : 'var(--accent)';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB ${ab.link ? `<a href="${escapeAttr(ab.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('IP Address', ab.ipAddress)}
      ${kv('IP Version', ab.ipVersion != null ? `IPv${ab.ipVersion}` : null)}
      ${kv('Is Public', ab.isPublic)}
      ${kv('Whitelisted', ab.isWhitelisted)}
      ${kv('Abuse Score', `${ab.score}%`, scoreCol)}
      ${kv('Usage Type', ab.usageType)}
      ${kv('ISP', ab.isp)}
      ${kv('Domain', ab.domain)}
      ${kv('Is Tor', ab.isTor)}
      ${kv('Total Reports', ab.totalReports != null ? String(ab.totalReports) : null)}
      ${kv('Last Reported', ab.lastReportedAt?.split('T')[0])}
    </div>
    ${ab.hostnames?.length ? `<div class="intel-sub-label">HOSTNAMES</div><div class="modal-tags">${ab.hostnames.slice(0,6).map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildOTXBlock(otx) {
  if (!otx || otx.skipped || otx.error) {
    const msg = otx?.error || otx?.reason || 'Not available';
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX</div><div class="intel-na">${escapeHtml(msg)}</div></div>`;
  }
  const pulseCol = otx.pulseCount >= 5 ? 'var(--red)' : otx.pulseCount >= 1 ? 'var(--yellow)' : 'var(--accent)';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX ${otx.link ? `<a href="${escapeAttr(otx.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('Pulse Count', String(otx.pulseCount), pulseCol)}
      ${kv('Subscriber Count', otx.subscriberCount > 0 ? String(otx.subscriberCount) : null)}
      ${kv('Indicator Count', otx.indicatorCount > 0 ? String(otx.indicatorCount) : null)}
      ${kv('Validation', otx.validation)}
      ${kv('Recent Pulse', otx.recentPulse ? truncate(otx.recentPulse, 44) : null)}
    </div>
    ${otx.pulseSources?.length ? `<div class="intel-sub-label">PULSE SOURCES</div><div class="modal-tags">${otx.pulseSources.map(s => `<span class="modal-tag">${escapeHtml(s)}</span>`).join('')}</div>` : ''}
    ${otx.malwareFamilies?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${otx.malwareFamilies.map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
    ${otx.adversaries?.length ? `<div class="intel-sub-label">ADVERSARIES</div><div class="modal-tags">${otx.adversaries.map(a => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(a)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildMBIntelBlock(mb) {
  if (!mb || mb.error)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(mb?.error || 'Not available')}</div></div>`;
  if (mb.skipped)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--muted)">${escapeHtml(mb.reason || 'Skipped')}</div></div>`;
  if (mb.notFound || !mb.count)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--accent)">Not found in malware database</div></div>`;
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div>
    <div class="modal-kv-grid">
      ${kv('Samples', String(mb.count), 'var(--red)')}
      ${kv('File Name', mb.fileName)}
      ${kv('File Type', mb.fileType)}
      ${kv('First Seen', mb.firstSeen)}
    </div>
    ${mb.families?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${mb.families.slice(0,5).map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function buildMainCard(title, col, content, link) {
  const lnk = link ? ` <a href="${escapeAttr(link)}" target="_blank" class="modal-link">↗</a>` : '';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:${col}">${title}${lnk}</div>
    ${content}
  </div>`;
}

function buildURLScanContent(us) {
  if (!us || us.skipped) return `<div class="intel-na">${escapeHtml(us?.reason || 'Skipped')}</div>`;
  if (us.error) return `<div class="intel-na">Error: ${escapeHtml(us.error)}</div>`;
  if (us.notFound || !us.total) return `<div class="intel-na" style="color:var(--accent)">No scans found</div>`;
  const lines = [`<div class="supp-kv"><span>Total Scans</span><span>${us.total}</span></div>`];
  if (us.maliciousCount) lines.push(`<div class="supp-kv"><span>Malicious</span><span style="color:var(--red)">${us.maliciousCount}</span></div>`);
  if (us.recent?.length) {
    lines.push(`<div style="margin-top:6px;font-size:11px;color:var(--muted);font-family:var(--mono)">RECENT SCANS</div>`);
    us.recent.slice(0, 3).forEach(r => lines.push(`<div class="supp-url-item ${r.malicious ? 'supp-url-mal' : ''}">${escapeHtml(truncate(r.domain || r.url, 36))} <span>${r.date}</span></div>`));
  }
  return lines.join('');
}

function buildThreatFoxContent(tf) {
  if (!tf || tf.skipped) return `<div class="intel-na">${escapeHtml(tf?.reason || 'Skipped')}</div>`;
  if (tf.error) return `<div class="intel-na">Error: ${escapeHtml(tf.error)}</div>`;
  if (tf.notFound) return `<div class="intel-na" style="color:var(--accent)">No IOCs found</div>`;
  const lines = [`<div class="supp-kv"><span>IOC Count</span><span style="color:var(--red)">${tf.iocCount}</span></div>`];
  if (tf.maxConfidence) lines.push(`<div class="supp-kv"><span>Confidence</span><span>${tf.maxConfidence}%</span></div>`);
  if (tf.firstSeen) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${tf.firstSeen}</span></div>`);
  if (tf.lastSeen)  lines.push(`<div class="supp-kv"><span>Last Seen</span><span>${tf.lastSeen}</span></div>`);
  if (tf.threatTypes?.length)     lines.push(`<div class="supp-kv"><span>Threat Type</span><span>${tf.threatTypes.join(', ')}</span></div>`);
  if (tf.malwareFamilies?.length) lines.push(`<div class="supp-kv"><span>Malware</span><span style="color:var(--red)">${tf.malwareFamilies.slice(0,3).join(', ')}</span></div>`);
  return lines.join('');
}

function buildURLhausContent(uh) {
  if (!uh || uh.skipped) return `<div class="intel-na">${escapeHtml(uh?.reason || 'Skipped')}</div>`;
  if (uh.error) return `<div class="intel-na">Error: ${escapeHtml(uh.error)}</div>`;
  if (uh.notFound) return `<div class="intel-na" style="color:var(--accent)">No URLs found</div>`;
  const lines = [`<div class="supp-kv"><span>URLs Listed</span><span style="color:var(--red)">${uh.urlsCount}</span></div>`];
  if (uh.onlineCount) lines.push(`<div class="supp-kv"><span>Online</span><span style="color:var(--red)">${uh.onlineCount}</span></div>`);
  if (uh.threats?.length) lines.push(`<div class="supp-kv"><span>Threat</span><span>${uh.threats.join(', ')}</span></div>`);
  if (uh.tags?.length)    lines.push(`<div class="supp-kv"><span>Tags</span><span>${uh.tags.join(', ')}</span></div>`);
  if (uh.dateAdded) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${uh.dateAdded}</span></div>`);
  return lines.join('');
}

function buildHAContent(ha) {
  if (!ha || ha.skipped) return `<div class="intel-na">${escapeHtml(ha?.reason || 'Skipped')}</div>`;
  if (ha.error) return `<div class="intel-na">Error: ${escapeHtml(ha.error)}</div>`;
  if (ha.notFound || !ha.count) return `<div class="intel-na" style="color:var(--accent)">No sandbox matches</div>`;
  const verdictCol = ha.verdict === 'malicious' ? 'var(--red)' : ha.verdict === 'suspicious' ? 'var(--yellow)' : 'var(--accent)';
  const lines = [];
  lines.push(`<div class="supp-kv"><span>Sandbox Hits</span><span>${ha.count}${ha.maliciousCount ? ` <span style="color:var(--red)">(${ha.maliciousCount} malicious)</span>` : ''}</span></div>`);
  if (ha.verdict)   lines.push(`<div class="supp-kv"><span>Verdict</span><span style="color:${verdictCol}">${ha.verdict.toUpperCase()}</span></div>`);
  if (ha.maxScore)  lines.push(`<div class="supp-kv"><span>Threat Score</span><span style="color:${verdictCol}">${ha.maxScore} / 100</span></div>`);
  if (ha.families?.length)  lines.push(`<div class="supp-kv"><span>Malware Family</span><span style="color:var(--red)">${ha.families.slice(0,3).map(escapeHtml).join(', ')}</span></div>`);
  if (ha.fileTypes?.length) lines.push(`<div class="supp-kv"><span>File Type</span><span>${ha.fileTypes.map(escapeHtml).join(', ')}</span></div>`);
  if (ha.submitNames?.length) lines.push(`<div class="supp-kv"><span>Submitted As</span><span>${ha.submitNames.slice(0,2).map(n => escapeHtml(truncate(n,40))).join(', ')}</span></div>`);
  if (ha.sha256)  lines.push(`<div class="supp-kv"><span>SHA-256</span><span style="font-size:10px;word-break:break-all">${escapeHtml(ha.sha256)}</span></div>`);
  if (ha.md5)     lines.push(`<div class="supp-kv"><span>MD5</span><span style="font-size:10px">${escapeHtml(ha.md5)}</span></div>`);
  if (ha.sha1)    lines.push(`<div class="supp-kv"><span>SHA-1</span><span style="font-size:10px">${escapeHtml(ha.sha1)}</span></div>`);
  if (ha.environments?.length) lines.push(`<div class="supp-kv"><span>Environments</span><span>${ha.environments.slice(0,3).map(escapeHtml).join(' · ')}</span></div>`);
  if (ha.tags?.length) lines.push(`<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:3px">${ha.tags.map(t => `<span class="modal-tag" style="color:var(--ha);border-color:rgba(132,204,22,.3)">${escapeHtml(t)}</span>`).join('')}</div>`);
  return lines.join('');
}

function buildMBContent(mb) {
  if (!mb || mb.skipped) return `<div class="intel-na">${escapeHtml(mb?.reason || 'Skipped')}</div>`;
  if (mb.error) return `<div class="intel-na">Error: ${escapeHtml(mb.error)}</div>`;
  if (mb.notFound || !mb.count) return `<div class="intel-na" style="color:var(--accent)">Not found</div>`;
  const lines = [
    mb.fileName ? `<div class="supp-kv"><span>File Name</span><span>${escapeHtml(mb.fileName)}</span></div>` : '',
    `<div class="supp-kv"><span>Samples</span><span style="color:var(--red)">${mb.count}</span></div>`,
  ];
  if (mb.fileType) lines.push(`<div class="supp-kv"><span>File Type</span><span>${escapeHtml(mb.fileType)}</span></div>`);
  if (mb.families?.length) lines.push(`<div class="supp-kv"><span>Families</span><span style="color:var(--red)">${mb.families.join(', ')}</span></div>`);
  if (mb.firstSeen) lines.push(`<div class="supp-kv"><span>First Seen</span><span>${mb.firstSeen}</span></div>`);
  return lines.filter(Boolean).join('');
}

/* ── Results meta ────────────────────────────────────────────────────────── */
function updateResultsMeta(results) {
  const done = results.filter(r => r.done).length;
  const el = document.getElementById('results-meta');
  if (el) el.innerHTML = `<span>${done}</span> / ${results.length} analyzed`;
}

/* ── Key save/load stubs ──────────────────────────────────────────────────── */
function saveKeys() {}
function clearKeys() {}
function loadSavedKeys() {}
function updateStatusDots() {}

function toggleKey(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.type = el.type === 'password' ? 'text' : 'password';
  const btn = el.nextElementSibling;
  if (btn) btn.textContent = el.type === 'password' ? 'SHOW' : 'HIDE';
}

function togglePanel(id) {
  const body = document.getElementById(id + '-body');
  const chev = document.getElementById(id + '-chevron');
  if (!body) return;
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  if (chev) chev.classList.toggle('closed', open);
}

function switchInputTab(tab, btn) {
  document.querySelectorAll('.input-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const pane = document.getElementById(`tab-${tab}`);
  if (pane) pane.classList.add('active');
}

function scanSingleIOC() {
  const input = document.getElementById('single-ip-input');
  const val = input?.value.trim();
  if (!val) return;
  document.getElementById('ip-input').value = val;
  parseIOCsRealtime();
  startScan();
  input.value = '';
}

function scanSingleIP() { scanSingleIOC(); }
function updateVTPaidUI() {}

/* ── IP Intel rendering ──────────────────────────────────────────────────── */
function renderIPIntelRows(results) {
  document.getElementById('ipintel-body').innerHTML = results.map((e, i) => buildIPIntelRow(e, i)).join('');
}

function buildIPIntelRow(entry, i) {
  const { ioc, iplocate, ab, vt, otx, threatfox, done } = entry;
  const il = (iplocate && !iplocate.skipped && !iplocate.error && !iplocate.notFound) ? iplocate : null;
  const nf = '<span class="ipi-nf">not found</span>';
  const ld = '<span class="src-loading">…</span>';

  const countryHtml = done ? (il?.country      ? escapeHtml(il.country) : nf) : ld;
  const orgHtml     = done ? (il?.organization ? escapeHtml(truncate(il.organization, 30)) : nf) : ld;
  const _abDomain   = (ab && !ab.skipped && !ab.error && ab.domain) ? ab.domain : null;
  const domainVal   = il?.domain || _abDomain || null;
  const domainHtml  = done ? (domainVal ? escapeHtml(domainVal) : nf) : ld;
  const flagsHtml   = done ? buildIPIntelFlags(il) : ld;

  const abScore = ab && !ab.skipped && !ab.error ? ab.score : null;
  const abHtml = done
    ? (abScore != null ? `<span style="font-weight:600;color:${abScore >= 75 ? 'var(--red)' : abScore >= 25 ? 'var(--yellow)' : 'var(--accent)'}">${abScore}%</span>` : nf)
    : ld;

  const vtMal   = vt && !vt.skipped && !vt.error && vt.total > 0 ? vt.malicious : null;
  const vtTotal = vt && !vt.skipped && !vt.error && vt.total > 0 ? vt.total     : null;
  const vtHtml = done
    ? (vtTotal != null ? `<span style="color:${vtMal > 0 ? 'var(--red)' : 'var(--accent)'}">${vtMal}/${vtTotal}</span>` : nf)
    : ld;

  const otxPulses = otx && !otx.skipped && !otx.error ? otx.pulseCount : null;
  const otxHtml = done
    ? (otxPulses != null ? `<span style="color:${otxPulses > 0 ? 'var(--yellow)' : 'var(--muted)'}">${otxPulses}</span>` : nf)
    : ld;

  const tfHits = threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound ? (threatfox.iocCount || 0) : null;
  const tfHtml = done
    ? (tfHits != null ? `<span style="color:${tfHits > 0 ? 'var(--red)' : 'var(--muted)'}">${tfHits}</span>` : nf)
    : ld;

  const copyHtml   = done ? `<button class="btn-ii-copy" onclick="copyIPIntelRow(${i})" title="Copy as key-value">⎘</button>` : '';
  const detailHtml = done ? `<button class="btn-detail" onclick="openIPIntelModal(${i})">DETAIL</button>` : ld;
  const aiBtnHtml  = done ? `<button class="btn-ai" onclick="toggleIPIntelAIPanel(${i})" title="AI analysis">AI</button>` : '';

  return `<tr data-row="${i}">
    <td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val" title="${escapeAttr(ioc.value)}">${escapeHtml(ioc.value)}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy IP">⎘</button>
      </div>
    </td>
    <td id="ii-ab-${i}"      class="col-iab">${abHtml}</td>
    <td id="ii-vt-${i}"      class="col-ivt">${vtHtml}</td>
    <td id="ii-otx-${i}"     class="col-iotx">${otxHtml}</td>
    <td id="ii-tf-${i}"      class="col-itf">${tfHtml}</td>
    <td id="ii-country-${i}" class="col-icountry">${countryHtml}</td>
    <td id="ii-org-${i}"     class="col-iorg">${orgHtml}</td>
    <td id="ii-domain-${i}"  class="col-idomain">${domainHtml}</td>
    <td id="ii-fl-${i}"      class="col-iflags">${flagsHtml}</td>
    <td id="ii-copy-${i}"    class="col-icopy">${copyHtml}</td>
    <td id="ii-det-${i}"     class="col-idetail">${detailHtml}</td>
    <td id="ii-ai-${i}"      class="col-ai">${aiBtnHtml}</td>
  </tr>`;
}

function buildIPIntelFlags(il) {
  if (!il) return '<span style="color:var(--muted)">-</span>';
  const defs = [
    ['is_abuser',      'ABUSER',  'var(--red)'],
    ['is_tor',         'TOR',     'var(--red)'],
    ['is_bogon',       'BOGON',   'var(--red)'],
    ['is_vpn',         'VPN',     '#facc15'],
    ['is_proxy',       'PROXY',   '#facc15'],
    ['is_anonymous',   'ANON',    '#facc15'],
    ['is_hosting',     'HOSTING', 'var(--accent2)'],
    ['is_icloud_relay','iCLOUD',  'var(--accent2)'],
  ];
  const active = defs.filter(([k]) => il[k] === true);
  if (!active.length) return '<span style="color:var(--accent)">CLEAN</span>';
  return active.map(([, label, color]) =>
    `<span class="ipi-flag" style="color:${color};border-color:${color}30">${label}</span>`
  ).join('');
}

function updateIPIntelRow(i, entry) {
  const { iplocate, ab, vt, otx, threatfox } = entry;
  const il = (iplocate && !iplocate.skipped && !iplocate.error && !iplocate.notFound) ? iplocate : null;
  const nf = '<span class="ipi-nf">not found</span>';
  const g  = id => document.getElementById(`${id}-${i}`);

  const countryEl = g('ii-country');
  const orgEl     = g('ii-org');
  const domainEl  = g('ii-domain');
  const flEl      = g('ii-fl');
  const abEl      = g('ii-ab');
  const vtEl      = g('ii-vt');
  const otxEl     = g('ii-otx');
  const tfEl      = g('ii-tf');
  const copyEl    = g('ii-copy');
  const detEl     = g('ii-det');

  if (countryEl) countryEl.innerHTML = il?.country      ? escapeHtml(il.country) : nf;
  if (orgEl)     orgEl.innerHTML     = il?.organization ? escapeHtml(truncate(il.organization, 30)) : nf;
  const _abDomain = (ab && !ab.skipped && !ab.error && ab.domain) ? ab.domain : null;
  const domainVal = il?.domain || _abDomain || null;
  if (domainEl)  domainEl.innerHTML  = domainVal ? escapeHtml(domainVal) : nf;
  if (flEl)      flEl.innerHTML      = buildIPIntelFlags(il);

  const abScore = ab && !ab.skipped && !ab.error ? ab.score : null;
  if (abEl) abEl.innerHTML = abScore != null
    ? `<span style="font-weight:600;color:${abScore >= 75 ? 'var(--red)' : abScore >= 25 ? 'var(--yellow)' : 'var(--accent)'}">${abScore}%</span>`
    : nf;

  const vtMal   = vt && !vt.skipped && !vt.error && vt.total > 0 ? vt.malicious : null;
  const vtTotal = vt && !vt.skipped && !vt.error && vt.total > 0 ? vt.total     : null;
  if (vtEl) vtEl.innerHTML = vtTotal != null
    ? `<span style="color:${vtMal > 0 ? 'var(--red)' : 'var(--accent)'}">${vtMal}/${vtTotal}</span>`
    : nf;

  const otxPulses = otx && !otx.skipped && !otx.error ? otx.pulseCount : null;
  if (otxEl) otxEl.innerHTML = otxPulses != null
    ? `<span style="color:${otxPulses > 0 ? 'var(--yellow)' : 'var(--muted)'}">${otxPulses}</span>`
    : nf;

  const tfHits = threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound ? (threatfox.iocCount || 0) : null;
  if (tfEl) tfEl.innerHTML = tfHits != null
    ? `<span style="color:${tfHits > 0 ? 'var(--red)' : 'var(--muted)'}">${tfHits}</span>`
    : nf;

  if (copyEl) copyEl.innerHTML = `<button class="btn-ii-copy" onclick="copyIPIntelRow(${i})" title="Copy as key-value">⎘</button>`;
  if (detEl)  detEl.innerHTML  = `<button class="btn-detail" onclick="openIPIntelModal(${i})">DETAIL</button>`;
  const aiEl = document.getElementById(`ii-ai-${i}`);
  if (aiEl) aiEl.innerHTML = `<button class="btn-ai" onclick="toggleIPIntelAIPanel(${i})" title="AI analysis">AI</button>`;
}

function openIPIntelModal(i) {
  const entry = ipIntelResults[i];
  if (!entry) return;
  const { ioc, iplocate, ab, vt, otx, threatfox } = entry;
  const il = (iplocate && !iplocate.skipped && !iplocate.error && !iplocate.notFound) ? iplocate : null;

  const abOk      = ab && !ab.skipped && !ab.error;
  const abScore   = abOk ? ab.score : null;
  const abReports = abOk ? (ab.totalReports ?? null) : null;
  const abIsp     = abOk ? (ab.isp || null) : null;
  const vtOk      = vt && !vt.skipped && !vt.error;
  const vtMal     = vtOk ? vt.malicious  : null;
  const vtSus     = vtOk ? vt.suspicious : null;
  const vtUndet   = vtOk ? vt.undetected : null;
  const vtTotal   = vtOk ? vt.total      : null;
  const otxPulses = otx && !otx.skipped && !otx.error ? otx.pulseCount : null;
  const tfHits    = threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound ? (threatfox.iocCount || 0) : null;

  const abDisplay = abScore != null
    ? `${abScore}% confidence${abReports != null ? ` — ${abReports.toLocaleString()} reports` : ''}${abIsp ? ` | ${abIsp}` : ''}`
    : null;
  const vtDisplay = (() => {
    if (vtTotal == null) return null;
    const parts = [];
    if (vtMal   > 0) parts.push(`${vtMal} malicious`);
    if (vtSus   > 0) parts.push(`${vtSus} suspicious`);
    if (parts.length) return `${parts.join(' · ')} out of ${vtTotal} engines`;
    if (vtUndet === vtTotal) return 'undetected';
    return `clean out of ${vtTotal} engines`;
  })();

  const row = (label, val) => {
    const isBool = typeof val === 'boolean';
    const isNull = val === null || val === undefined;
    const color   = isNull ? 'var(--muted)' : isBool ? (val ? 'var(--red)' : 'var(--accent)') : 'var(--text)';
    const display = isNull ? 'not found' : isBool ? (val ? 'YES' : 'no') : escapeHtml(String(val));
    return `<tr><td class="iim-key">${escapeHtml(label)}</td><td class="iim-val" style="color:${color}">${display}</td></tr>`;
  };

  const flagsHtml = buildIPIntelFlags(il);

  const html = `<div class="iim-wrap">
    <div class="iim-section-label">THREAT INTELLIGENCE</div>
    <table class="iim-table">
      ${row('AbuseIPDB Score', abDisplay)}
      ${row('VirusTotal Detections', vtDisplay)}
      ${row('OTX Pulses', otxPulses != null ? `${otxPulses} pulse${otxPulses !== 1 ? 's' : ''}` : null)}
      ${row('ThreatFox Hits', tfHits != null ? `${tfHits} IOC match${tfHits !== 1 ? 'es' : ''}` : null)}
    </table>
    <div class="iim-links">
      ${vt?.link        ? `<a href="${escapeAttr(vt.link)}"        target="_blank" rel="noopener" class="modal-ext-link">VirusTotal ↗</a>`  : ''}
      ${ab?.link        ? `<a href="${escapeAttr(ab.link)}"        target="_blank" rel="noopener" class="modal-ext-link">AbuseIPDB ↗</a>`   : ''}
      ${otx?.link       ? `<a href="${escapeAttr(otx.link)}"       target="_blank" rel="noopener" class="modal-ext-link">OTX ↗</a>`         : ''}
      ${threatfox?.link ? `<a href="${escapeAttr(threatfox.link)}" target="_blank" rel="noopener" class="modal-ext-link">ThreatFox ↗</a>`   : ''}
    </div>
    <div class="iim-section-label">LOCATION <span style="font-size:9px;color:var(--muted);font-weight:400;letter-spacing:.5px">· IPLOCATE</span></div>
    <table class="iim-table">
      ${row('IP Address', il?.ip || ioc.value)}
      ${row('Country', il?.country || null)}
      ${row('City', il?.city || null)}
      ${row('Subdivision', il?.subdivision || null)}
      ${row('Continent', il?.continent || null)}
      ${row('Time Zone', il?.time_zone || null)}
    </table>
    <div class="iim-section-label">NETWORK <span style="font-size:9px;color:var(--muted);font-weight:400;letter-spacing:.5px">· IPLOCATE</span></div>
    <table class="iim-table">
      ${row('Network', il?.network || null)}
      ${row('ASN', il?.asn || null)}
      ${row('ASN Name', il?.asn_name || null)}
      ${row('ISP', il?.isp || null)}
      ${row('Organization', il?.organization || null)}
      ${row('Domain', il?.domain || ((ab && !ab.skipped && !ab.error && ab.domain) ? ab.domain : null) || null)}
    </table>
    <div class="iim-section-label">PRIVACY FLAGS <span style="font-size:9px;color:var(--muted);font-weight:400;letter-spacing:.5px">· IPLOCATE</span></div>
    <div style="margin-bottom:10px">${flagsHtml}</div>
    <table class="iim-table">
      ${row('Is Abuser', il?.is_abuser ?? null)}
      ${row('Is Anonymous', il?.is_anonymous ?? null)}
      ${row('Is VPN', il?.is_vpn ?? null)}
      ${row('Is Proxy', il?.is_proxy ?? null)}
      ${row('Is Tor', il?.is_tor ?? null)}
      ${row('Is Hosting', il?.is_hosting ?? null)}
      ${row('Is iCloud Relay', il?.is_icloud_relay ?? null)}
      ${row('Is Bogon', il?.is_bogon ?? null)}
    </table>
  </div>`;

  document.getElementById('modal-title').innerHTML = `IP INTEL <span style="color:var(--accent2)">${escapeHtml(ioc.value)}</span>`;
  document.getElementById('modal-header-actions').innerHTML =
    `<button class="btn btn-export" onclick="iiClipboard(ipIntelEntryToKV(ipIntelResults[${i}]),'Copied to clipboard')" title="Copy all fields as key-value">
       <svg width="11" height="11" viewBox="0 0 12 12" fill="none"><rect x="1" y="3" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.2"/><path d="M3 1h8v8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
       COPY
     </button>`;
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').classList.add('open');
}

/* ── IP Intel copy / export ──────────────────────────────────────────────── */
const II_EXPORT_HEADERS = [
  'IP Address',
  'AbuseIPDB Score (%)', 'VirusTotal', 'OTX Pulses', 'ThreatFox Hits',
  'Country', 'City',
  'Network', 'ASN', 'ASN Name', 'ISP', 'Organization', 'Domain',
  'Is Abuser', 'Is Anonymous', 'Is VPN', 'Is Proxy', 'Is Tor', 'Is Hosting',
  'Is iCloud Relay', 'Is Bogon',
];

function _iiBase(entry) {
  const { ioc, iplocate, ab, vt, otx, threatfox } = entry;
  const il         = (iplocate && !iplocate.skipped && !iplocate.error && !iplocate.notFound) ? iplocate : null;
  const abOk       = ab && !ab.skipped && !ab.error;
  const abScore    = abOk ? ab.score : null;
  const abReports  = abOk ? (ab.totalReports ?? null) : null;
  const abIsp      = abOk ? (ab.isp || null) : null;
  const vtOk       = vt && !vt.skipped && !vt.error;
  const vtMal      = vtOk ? vt.malicious   : null;
  const vtSus      = vtOk ? vt.suspicious  : null;
  const vtUndet    = vtOk ? vt.undetected  : null;
  const vtTotal    = vtOk ? vt.total       : null;
  const otxP       = otx && !otx.skipped && !otx.error ? otx.pulseCount : null;
  const tfH        = threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound ? (threatfox.iocCount || 0) : null;
  const vtStr      = vtTotal != null ? `${vtMal}/${vtTotal}` : null;
  const domainVal  = il?.domain || (abOk && ab.domain ? ab.domain : null) || null;
  return { ioc, il, abScore, abReports, abIsp, vtMal, vtSus, vtUndet, vtTotal, vtStr, otxP, tfH, domainVal };
}

function ipIntelEntryToKV(entry) {
  const { ioc, il, abScore, abReports, abIsp, vtMal, vtSus, vtUndet, vtTotal, vtStr, otxP, tfH, domainVal } = _iiBase(entry);
  const v = (val) => val != null ? String(val) : 'not found';
  const abLine = abScore != null
    ? `${abScore}% confidence${abReports != null ? ` — ${abReports.toLocaleString()} reports` : ''}${abIsp ? ` | ${abIsp}` : ''}`
    : 'not found';
  const vtLine = (() => {
    if (vtTotal == null) return 'not found';
    const parts = [];
    if (vtMal   > 0) parts.push(`${vtMal} malicious`);
    if (vtSus   > 0) parts.push(`${vtSus} suspicious`);
    if (parts.length) return `${parts.join(' · ')} out of ${vtTotal} engines`;
    if (vtUndet === vtTotal) return 'undetected';
    return `clean out of ${vtTotal} engines`;
  })();
  const otxLine = otxP != null ? `${otxP} pulse${otxP !== 1 ? 's' : ''}` : 'not found';
  const tfLine  = tfH  != null ? `${tfH} IOC match${tfH  !== 1 ? 'es' : ''}` : 'not found';
  return [
    `IP Address: ${ioc.value}`,
    `AbuseIPDB Score: ${abLine}`,
    `VirusTotal: ${vtLine}`,
    `OTX Pulses: ${otxLine}`,
    `ThreatFox Hits: ${tfLine}`,
    `Country: ${v(il?.country)}`,
    `City: ${v(il?.city)}`,
    `Network: ${v(il?.network)}`,
    `ASN: ${v(il?.asn)}`,
    `ASN Name: ${v(il?.asn_name)}`,
    `ISP: ${v(il?.isp)}`,
    `Organization: ${v(il?.organization)}`,
    `Domain: ${v(domainVal)}`,
    `Is Abuser: ${il == null ? 'not found' : String(il.is_abuser)}`,
    `Is Anonymous: ${il == null ? 'not found' : String(il.is_anonymous)}`,
    `Is VPN: ${il == null ? 'not found' : String(il.is_vpn)}`,
    `Is Proxy: ${il == null ? 'not found' : String(il.is_proxy)}`,
    `Is Tor: ${il == null ? 'not found' : String(il.is_tor)}`,
    `Is Hosting: ${il == null ? 'not found' : String(il.is_hosting)}`,
    `Is iCloud Relay: ${il == null ? 'not found' : String(il.is_icloud_relay)}`,
    `Is Bogon: ${il == null ? 'not found' : String(il.is_bogon)}`,
  ].join('\n');
}

function ipIntelEntryToTSV(entry) {
  const { ioc, il, abScore, vtStr, otxP, tfH, domainVal } = _iiBase(entry);
  const b = v => v == null ? '' : String(v);
  return [
    ioc.value,
    abScore != null ? String(abScore) : '',
    vtStr   ?? '',
    otxP    != null ? String(otxP) : '',
    tfH     != null ? String(tfH)  : '',
    b(il?.country), b(il?.city),
    b(il?.network), b(il?.asn), b(il?.asn_name), b(il?.isp), b(il?.organization), b(domainVal),
    b(il?.is_abuser), b(il?.is_anonymous), b(il?.is_vpn), b(il?.is_proxy), b(il?.is_tor), b(il?.is_hosting),
    b(il?.is_icloud_relay), b(il?.is_bogon),
  ].join('\t');
}

function iiClipboard(text, msg) {
  const fallback = () => {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); showToast(msg, 'success'); }
    catch(_) { showToast('Copy failed — use Ctrl+C', 'error'); }
    document.body.removeChild(ta);
  };
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => showToast(msg, 'success')).catch(fallback);
  } else { fallback(); }
}

window.copyAllIPIntelIPs = function() {
  if (!ipIntelResults?.length) { showToast('No IPs to copy', 'warning'); return; }
  const ips = ipIntelResults.map(e => e.ioc.value).join('\n');
  navigator.clipboard.writeText(ips).then(() => showToast(`${ipIntelResults.length} IP${ipIntelResults.length > 1 ? 's' : ''} copied`, 'success'));
};

function copyIPIntelRow(i) {
  const entry = ipIntelResults[i];
  if (!entry || !entry.done) { showToast('Row not ready', 'warning'); return; }
  iiClipboard(ipIntelEntryToKV(entry), 'Copied to clipboard');
}

function copyIPIntelTable() {
  if (!ipIntelResults.length) { showToast('No results to copy', 'warning'); return; }
  const n = ipIntelResults.length;
  let text;
  if (n <= 5) {
    text = ipIntelResults.map(ipIntelEntryToKV).join('\n\n' + '─'.repeat(40) + '\n\n');
  } else {
    const header = II_EXPORT_HEADERS.join('\t');
    text = header + '\n' + ipIntelResults.map(ipIntelEntryToTSV).join('\n');
  }
  iiClipboard(text, `${n} IP${n !== 1 ? 's' : ''} copied to clipboard`);
}

function exportIPIntelExcel() {
  if (!ipIntelResults.length) { showToast('No results to export', 'warning'); return; }
  if (typeof XLSX === 'undefined') { showToast('Excel library not ready — reload the page', 'error'); return; }
  const rows = ipIntelResults.map(entry => {
    const { ioc, il, abScore, vtStr, otxP, tfH, domainVal } = _iiBase(entry);
    return [
      ioc.value,
      abScore != null ? abScore : null,
      vtStr ?? null,
      otxP   != null ? otxP   : null,
      tfH    != null ? tfH    : null,
      il?.country ?? null, il?.city ?? null,
      il?.network ?? null, il?.asn ?? null, il?.asn_name ?? null, il?.isp ?? null, il?.organization ?? null, domainVal ?? null,
      il?.is_abuser ?? null, il?.is_anonymous ?? null, il?.is_vpn ?? null, il?.is_proxy ?? null, il?.is_tor ?? null, il?.is_hosting ?? null,
      il?.is_icloud_relay ?? null, il?.is_bogon ?? null,
    ];
  });
  const headers = [
    'IP Address',
    'AbuseIPDB Score (%)', 'VirusTotal', 'OTX Pulses', 'ThreatFox Hits',
    'Country', 'City',
    'Network', 'ASN', 'ASN Name', 'ISP', 'Organization', 'Domain',
    'Is Abuser', 'Is Anonymous', 'Is VPN', 'Is Proxy', 'Is Tor', 'Is Hosting',
    'Is iCloud Relay', 'Is Bogon',
  ];
  const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'IP Intel');
  XLSX.writeFile(wb, 'ip-intel-results.xlsx');
  showToast('Exported to ip-intel-results.xlsx', 'success');
}
