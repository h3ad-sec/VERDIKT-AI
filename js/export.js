
/* ── X-VERDIKT Export Engine ─────────────────────────────────────────────── */

function getExportRows(order) {
  let rows = scanResults.filter(r => r.done);
  if (order === 'type') {
    rows = [...rows].sort((a, b) => a.ioc.type.localeCompare(b.ioc.type));
  }
  return rows;
}

function rowToFlat(entry) {
  const srcVal = (src, fn) => {
    if (!src || src.skipped) return '-';
    if (src.error) return `Error: ${src.error}`;
    return fn(src) ?? '-';
  };
  const aiResult = (typeof _aiCache !== 'undefined') ? _aiCache.get(entry.ioc.value) : null;
  const base = {
    'IOC':           entry.ioc.value,
    'Type':          entry.ioc.label,
    'VT':            srcVal(entry.vt,       s => `${s.malicious||0}/${s.total||0}`),
    'AbuseIPDB':     srcVal(entry.ab,       s => `${s.score||0}%`),
    'OTX':           srcVal(entry.otx,      s => `${s.pulseCount ?? 0} pulses`),
    'ThreatFox':     srcVal(entry.threatfox,s => s.notFound ? 'No C2'    : `${s.iocCount} C2`),
    'URLScan':       srcVal(entry.urlscan,  s => s.notFound ? 'No scans' : `${s.maliciousCount||0}/${s.total||0} mal`),
    'URLhaus':       srcVal(entry.urlhaus,  s => s.notFound ? 'Not found': `${s.urlsCount||0} URLs`),
    'MalwareBazaar': srcVal(entry.mb,       s => s.notFound ? 'Clean'    : `${s.count||0} samples`),
    'HybridAnalysis':srcVal(entry.ha,       s => s.notFound ? 'No hits'  : `${s.count||0} hits`),
    'AI_Narrative':  aiResult ? aiResult.narrative : '',
    'AI_MITRE':      aiResult ? aiResult.mitre.map(t => `${t.id} ${t.name}`).join('; ') : '',
    'AI_KQL':        aiResult ? aiResult.queries.kql   : '',
    'AI_SPL':        aiResult ? aiResult.queries.spl   : '',
    'AI_Sigma':      aiResult ? aiResult.queries.sigma : '',
    'AI_XQL':        aiResult ? aiResult.queries.xql   : '',
  };
  const isIP = entry.ioc.type === 'ip' || entry.ioc.type === 'ipv6';
  if (!isIP) return base;
  return {
    ...base,
    'VT_IP':              srcVal(entry.vt, s => s.ip),
    'VT_ASN':             srcVal(entry.vt, s => s.asn != null ? 'AS' + s.asn : null),
    'VT_AS_Owner':        srcVal(entry.vt, s => s.as_owner),
    'VT_Country':         srcVal(entry.vt, s => s.country),
    'VT_Reputation':      srcVal(entry.vt, s => s.reputation != null ? String(s.reputation) : null),
    'VT_Detections':      srcVal(entry.vt, s => `${s.malicious||0}/${s.total||0} engines`),
    'VT_Network':         srcVal(entry.vt, s => s.network),
    'VT_JARM':            srcVal(entry.vt, s => s.jarm),
    'VT_Tags':            srcVal(entry.vt, s => s.tags?.join('; ')),
    'VT_Cert_SubjectCN':  srcVal(entry.vt, s => s.cert_subject_cn),
    'VT_Cert_IssuerCN':   srcVal(entry.vt, s => s.cert_issuer_cn),
    'VT_Cert_SelfSigned': srcVal(entry.vt, s => s.cert_self_signed != null ? String(s.cert_self_signed) : null),
    'VT_Cert_ValidUntil': srcVal(entry.vt, s => s.cert_valid_until),
    'VT_Cert_SHA256':     srcVal(entry.vt, s => s.cert_thumbprint),
    'AB_IPAddress':       srcVal(entry.ab, s => s.ipAddress),
    'AB_IsPublic':        srcVal(entry.ab, s => s.isPublic != null ? String(s.isPublic) : null),
    'AB_IPVersion':       srcVal(entry.ab, s => s.ipVersion != null ? 'IPv' + s.ipVersion : null),
    'AB_IsWhitelisted':   srcVal(entry.ab, s => s.isWhitelisted != null ? String(s.isWhitelisted) : null),
    'AB_AbuseScore':      srcVal(entry.ab, s => `${s.score||0}%`),
    'AB_UsageType':       srcVal(entry.ab, s => s.usageType),
    'AB_ISP':             srcVal(entry.ab, s => s.isp),
    'AB_Domain':          srcVal(entry.ab, s => s.domain),
    'AB_Hostnames':       srcVal(entry.ab, s => s.hostnames?.join('; ')),
    'AB_IsTor':           srcVal(entry.ab, s => String(s.isTor)),
    'OTX_PulseCount':     srcVal(entry.otx, s => String(s.pulseCount)),
    'OTX_Subscribers':    srcVal(entry.otx, s => String(s.subscriberCount || 0)),
    'OTX_IndicatorCount': srcVal(entry.otx, s => String(s.indicatorCount || 0)),
    'OTX_Validation':     srcVal(entry.otx, s => s.validation),
    'OTX_PulseSources':   srcVal(entry.otx, s => s.pulseSources?.join('; ')),
  };
}

function downloadFile(content, filename, mimeType) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function expDateTag() { return new Date().toISOString().slice(0, 10); }

/* ── CSV ──────────────────────────────────────────────────────────────────── */
function exportCSV(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const flat = rows.map(rowToFlat);
  const headers = [...new Set(flat.flatMap(r => Object.keys(r)))];
  const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [
    headers.map(escape).join(','),
    ...flat.map(r => headers.map(h => escape(r[h] ?? '')).join(',')),
  ];
  downloadFile('﻿' + lines.join('\r\n'), `x-verdikt-${order}-${expDateTag()}.csv`, 'text/csv;charset=utf-8;');
  showToast(`CSV exported - ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── JSON ─────────────────────────────────────────────────────────────────── */
function exportJSON(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  let out;
  if (order === 'type') {
    out = {};
    for (const r of rows) { const k = r.ioc.type; (out[k] = out[k] || []).push(rowToFlat(r)); }
  } else {
    out = rows.map(rowToFlat);
  }
  downloadFile(JSON.stringify(out, null, 2), `x-verdikt-${order}-${expDateTag()}.json`, 'application/json');
  showToast(`JSON exported - ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Markdown ─────────────────────────────────────────────────────────────── */
function exportMarkdown(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const cols = ['IOC', 'Type', 'VT', 'AbuseIPDB', 'OTX', 'ThreatFox', 'URLScan', 'URLhaus', 'MalwareBazaar', 'HybridAnalysis'];
  const esc  = v => String(v ?? '-').replace(/\|/g, '\\|');
  const mkTable = list => {
    const hdr = '| ' + cols.join(' | ') + ' |';
    const sep = '| ' + cols.map(() => '---').join(' | ') + ' |';
    const body = list.map(r => '| ' + cols.map(c => esc(rowToFlat(r)[c])).join(' | ') + ' |').join('\n');
    return `${hdr}\n${sep}\n${body}`;
  };
  let md = `# VERDIKT-AI Export\n_Generated: ${new Date().toISOString()}_\n\n`;
  if (order === 'type') {
    const groups = {};
    for (const r of rows) { (groups[r.ioc.type] = groups[r.ioc.type] || []).push(r); }
    md += Object.entries(groups).map(([k, rs]) => `## ${k.toUpperCase()} (${rs.length})\n\n${mkTable(rs)}`).join('\n\n');
  } else {
    md += mkTable(rows);
  }
  downloadFile(md, `x-verdikt-${order}-${expDateTag()}.md`, 'text/markdown;charset=utf-8;');
  showToast(`Markdown exported - ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Excel (.xlsx via SheetJS) ───────────────────────────────────────────── */
function exportExcel(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  if (typeof XLSX === 'undefined') { showToast('Excel library not ready - refresh and try again', 'error'); return; }
  const wb = XLSX.utils.book_new();
  if (order === 'type') {
    const groups = {};
    for (const r of rows) { (groups[r.ioc.type] = groups[r.ioc.type] || []).push(rowToFlat(r)); }
    for (const [k, rs] of Object.entries(groups))
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rs), k.slice(0, 31));
  } else {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows.map(rowToFlat)), 'Results');
  }
  XLSX.writeFile(wb, `x-verdikt-${order}-${expDateTag()}.xlsx`);
  showToast(`Excel exported - ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── Export modal ────────────────────────────────────────────────────────── */
function openExportModal() {
  if (!scanResults.filter(r => r.done).length) {
    showToast('No completed results to export', 'error');
    return;
  }
  document.getElementById('export-modal')?.classList.add('open');
}

function closeExportModal(e) {
  if (e && e.target !== document.getElementById('export-modal')) return;
  document.getElementById('export-modal')?.classList.remove('open');
}

function doExport() {
  const fmt   = document.querySelector('input[name="exp-fmt"]:checked')?.value   || 'csv';
  const order = document.querySelector('input[name="exp-order"]:checked')?.value || 'serial';
  document.getElementById('export-modal')?.classList.remove('open');
  if (fmt === 'csv')  exportCSV(order);
  else if (fmt === 'json') exportJSON(order);
  else if (fmt === 'md')   exportMarkdown(order);
  else if (fmt === 'xls')  exportExcel(order);
}
