
let scanResults   = [];
let isScanning    = false;
let stopRequested = false;
let totalScanned  = 0;

const VtBucket = {
  tokens: 4, max: 4, refillRate: 4,
  lastRefill: Date.now(), paid: false,
  async acquire() {
    if (this.paid) return;
    const now = Date.now();
    this.tokens = Math.min(this.max, this.tokens + ((now - this.lastRefill) / 60000) * this.refillRate);
    this.lastRefill = now;
    if (this.tokens >= 1) { this.tokens--; return; }
    const waitMs = ((1 - this.tokens) / this.refillRate) * 60000;
    updateProgressSub(`VT rate limit — waiting ${Math.ceil(waitMs / 1000)}s…`);
    await sleep(waitMs);
    this.tokens = 0; this.lastRefill = Date.now();
  }
};

async function fetchWithRetry(fn, retries = 2, ms = 10000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), ms);
      const r = await fn(ctrl.signal);
      clearTimeout(t); return r;
    } catch(e) {
      if (i === retries) throw e;
      if (e.name === 'AbortError') throw new Error('Timeout');
      await sleep(1000 * (i + 1));
    }
  }
}

async function startScan() {
  if (typeof currentMode !== 'undefined' && currentMode === 'ipintel')  return startIPIntelScan();
  const raw = getInputText();
  if (!raw?.trim()) return;

  let { iocs } = parseIOCsWithMeta(raw);
  if (typeof filterIOCsByMode === 'function' && typeof currentMode !== 'undefined')
    iocs = filterIOCsByMode(iocs, currentMode);
  if (!iocs.length) { showToast('No valid IOCs detected', 'error'); return; }

  const privateCount = iocs.filter(i => i.isPrivate).length;
  if (privateCount > 0)
    showToast(`${privateCount} private IP${privateCount > 1 ? 's' : ''} detected — will skip external queries`, 'warning');

  VtBucket.paid = window._serverVTPaid === true;
  VtBucket.tokens = 4; VtBucket.lastRefill = Date.now();

  isScanning = true; stopRequested = false; scanResults = []; totalScanned = 0;

  for (const ioc of iocs) {
    scanResults.push({
      ioc, vt: null, ab: null, otx: null,
      urlscan: null, threatfox: null, urlhaus: null,
      mb: null, ha: null, done: false,
    });
  }

  document.getElementById('results-panel').style.display = '';
  document.getElementById('ipintel-panel').style.display  = 'none';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');

  renderResultRows(scanResults);
  renderSummary(scanResults);

  for (let i = 0; i < iocs.length; i++) {
    if (stopRequested) break;
    const ioc = iocs[i], entry = scanResults[i];
    updateProgress(i, iocs.length, ioc.value);
    updateRowLoading(i);
    await runParallelScan(entry);
    entry.done = true;
    totalScanned++;
    updateRow(i, entry);
    renderSummary(scanResults);
    updateHeaderCount();
  }

  isScanning = false;
  updateProgress(totalScanned, iocs.length, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display = 'none'; }, 2000);
  const n = iocs.length;
  showToast(
    stopRequested
      ? `Stopped — ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed`
      : `X-VERDIKT complete — ${n} IOC${n !== 1 ? 's' : ''} analyzed`,
    'success'
  );
}

/* Sources active per IOC type:
   vt ab otx us tf uh mb ha
   IP:     ✓  ✓  ✓   ✗  ✓  ✗  ✗  ✗
   IPv6:   ✓  ✓  ✓   ✗  ✓  ✗  ✗  ✗
   Hash:   ✓  ✗  ✓   ✗  ✓  ✗  ✓  ✓
   Domain: ✓  ✗  ✓   ✓  ✓  ✗  ✗  ✗
   URL:    ✓  ✗  ✓   ✓  ✗  ✓  ✗  ✗  */
const TYPE_SOURCES = {
  ip:          { ab:1, us:0, tf:1, uh:0, mb:0, ha:0 },
  ipv6:        { ab:1, us:0, tf:1, uh:0, mb:0, ha:0 },
  hash_md5:    { ab:0, us:0, tf:1, uh:0, mb:1, ha:1 },
  hash_sha1:   { ab:0, us:0, tf:1, uh:0, mb:1, ha:1 },
  hash_sha256: { ab:0, us:0, tf:1, uh:0, mb:1, ha:1 },
  hash_sha512: { ab:0, us:0, tf:1, uh:0, mb:1, ha:0 },
  domain:      { ab:0, us:1, tf:1, uh:0, mb:0, ha:0 },
  url:         { ab:0, us:1, tf:0, uh:1, mb:0, ha:0 },
};

async function runParallelScan(entry) {
  const { ioc } = entry;
  const t = ioc.type;

  if (ioc.isPrivate) {
    const skip = s => ({ source: s, skipped: true, reason: 'Private IP — skipped' });
    entry.vt = skip('virustotal'); entry.ab = skip('abuseipdb'); entry.otx = skip('otx');
    entry.urlscan = skip('urlscan'); entry.threatfox = skip('threatfox');
    entry.urlhaus = skip('urlhaus'); entry.mb = skip('malwarebazaar');
    entry.ha = skip('hybridanalysis');
    return;
  }

  const m = TYPE_SOURCES[t] || { ab:0, us:0, tf:1, uh:0, mb:0, ha:0, sh:0, fs:0 };
  const off = (s, r) => Promise.resolve({ source: s, skipped: true, reason: r || 'N/A for this IOC type' });

  const vtP = (async () => {
    await VtBucket.acquire();
    return fetchWithRetry(sig => API.virusTotal(ioc, sig)).catch(e => ({ source: 'virustotal', error: e.message }));
  })();

  const abP  = m.ab ? fetchWithRetry(sig => API.abuseIPDB(ioc, sig)).catch(e => ({ source: 'abuseipdb',    error: e.message })) : off('abuseipdb');
  const otxP = fetchWithRetry(sig => API.otx(ioc, sig)).catch(e => ({ source: 'otx', error: e.message }));
  const usP  = m.us ? fetchWithRetry(sig => API.urlscan(ioc, sig))   .catch(e => ({ source: 'urlscan',      error: e.message })) : off('urlscan');
  const tfP  = m.tf ? fetchWithRetry(sig => API.threatfox(ioc, sig)) .catch(e => ({ source: 'threatfox',    error: e.message })) : off('threatfox');
  const uhP  = m.uh ? fetchWithRetry(sig => API.urlhaus(ioc, sig))   .catch(e => ({ source: 'urlhaus',      error: e.message })) : off('urlhaus');
  const mbP  = m.mb ? fetchWithRetry(sig => API.malwarebazaar(ioc, sig)).catch(e => ({ source: 'malwarebazaar', skipped: true, reason: e.message })) : off('malwarebazaar');
  const haP  = m.ha ? fetchWithRetry(sig => API.hybridanalysis(ioc, sig)).catch(e => ({ source: 'hybridanalysis', error: e.message })) : off('hybridanalysis');

  const [vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha] =
    await Promise.all([vtP, abP, otxP, usP, tfP, uhP, mbP, haP]);

  entry.vt = vt; entry.ab = ab; entry.otx = otx;
  entry.urlscan = urlscan; entry.threatfox = threatfox; entry.urlhaus = urlhaus;
  entry.mb = mb; entry.ha = ha;
}

function stopScan() { stopRequested = true; showToast('Stopping after current IOC…', 'warning'); }

function setScanBtnState(state) {
  const btn = document.getElementById('scan-btn'), stop = document.getElementById('stop-btn');
  if (state === 'scanning') {
    btn.disabled = true; btn.style.display = 'none'; stop.style.display = '';
  } else {
    btn.disabled = false; btn.style.display = ''; stop.style.display = 'none';
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M7 4.5v2.5l1.8 1.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> ANALYZE`;
  }
}

function updateProgress(done, total, label) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-stats').textContent = `${done} / ${total}`;
  const complete = label === 'Complete' || label === 'Stopped' || done >= total;
  document.getElementById('progress-label').textContent = complete ? 'X-VERDIKT COMPLETE' : 'ANALYZING…';
  document.getElementById('progress-sub').innerHTML = complete
    ? `<span style="color:var(--accent)">✓ ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed</span><span style="color:var(--muted)">${pct}%</span>`
    : `<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%">${escapeHtml(label)}</span><span style="color:var(--muted)">${pct}%</span>`;
}
function updateProgressSub(msg) { const el = document.getElementById('progress-sub'); if (el) el.innerHTML = `<span style="color:var(--yellow)">${escapeHtml(msg)}</span>`; }
function updateHeaderCount() { const el = document.getElementById('session-count'); if (el) el.textContent = totalScanned; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── IP Intel scan ───────────────────────────────────────────────────────── */
let ipIntelResults = [];

async function startIPIntelScan() {
  const raw = getInputText();
  if (!raw?.trim()) return;

  let { iocs } = parseIOCsWithMeta(raw);
  iocs = iocs.filter(i => i.type === 'ip' || i.type === 'ipv6');
  if (!iocs.length) { showToast('No IPv4/IPv6 addresses found', 'error'); return; }

  const privateCount = iocs.filter(i => i.isPrivate).length;
  if (privateCount > 0)
    showToast(`${privateCount} private IP${privateCount > 1 ? 's' : ''} detected — will skip external queries`, 'warning');

  VtBucket.paid = window._serverVTPaid === true;
  VtBucket.tokens = 4; VtBucket.lastRefill = Date.now();

  isScanning = true; stopRequested = false; ipIntelResults = []; window.ipIntelResults = ipIntelResults; totalScanned = 0;

  for (const ioc of iocs) {
    ipIntelResults.push({ ioc, iplocate: null, ab: null, vt: null, otx: null, threatfox: null, done: false });
  }

  document.getElementById('results-panel').style.display  = 'none';
  document.getElementById('ipintel-panel').style.display  = '';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');
  renderIPIntelRows(ipIntelResults);

  for (let i = 0; i < iocs.length; i++) {
    if (stopRequested) break;
    const ioc = iocs[i], entry = ipIntelResults[i];
    updateProgress(i, iocs.length, ioc.value);
    await runIPIntelParallelScan(entry);
    entry.done = true;
    totalScanned++;
    updateIPIntelRow(i, entry);
  }

  isScanning = false;
  updateProgress(totalScanned, iocs.length, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display = 'none'; }, 2000);
  const n = iocs.length;
  showToast(
    stopRequested
      ? `Stopped — ${totalScanned} IP${totalScanned !== 1 ? 's' : ''} enriched`
      : `IP Intel complete — ${n} IP${n !== 1 ? 's' : ''} enriched`,
    'success'
  );
}

async function runIPIntelParallelScan(entry) {
  const { ioc } = entry;
  if (ioc.isPrivate) {
    const skip = s => ({ source: s, skipped: true, reason: 'Private IP — skipped' });
    entry.iplocate = skip('iplocate'); entry.ab = skip('abuseipdb');
    entry.vt = skip('virustotal'); entry.otx = skip('otx'); entry.threatfox = skip('threatfox');
    return;
  }
  const vtP = (async () => {
    await VtBucket.acquire();
    return fetchWithRetry(sig => API.virusTotal(ioc, sig)).catch(e => ({ source: 'virustotal', error: e.message }));
  })();
  const ilP  = fetchWithRetry(sig => API.iplocate(ioc, sig)).catch(e => ({ source: 'iplocate', error: e.message }));
  const abP  = fetchWithRetry(sig => API.abuseIPDB(ioc, sig)).catch(e => ({ source: 'abuseipdb', error: e.message }));
  const otxP = fetchWithRetry(sig => API.otx(ioc, sig)).catch(e => ({ source: 'otx', error: e.message }));
  const tfP  = fetchWithRetry(sig => API.threatfox(ioc, sig)).catch(e => ({ source: 'threatfox', error: e.message }));
  const [iplocate, ab, vt, otx, threatfox] = await Promise.all([ilP, abP, vtP, otxP, tfP]);
  entry.iplocate = iplocate; entry.ab = ab; entry.vt = vt; entry.otx = otx; entry.threatfox = threatfox;
}
