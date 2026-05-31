/* ── VERDIKT-AI · AI Analysis Engine ─────────────────────────────────────── */

const AI_SYSTEM_PROMPT = `You are an L3 SOC analyst and threat hunter with expertise in APT tracking, malware analysis, and production SIEM rule authoring for critical infrastructure environments.

STRICT DATA DISCIPLINE:
- Never invent artifact values, malware families, threat actor names, or MITRE technique IDs not present in the enrichment input.
- If input is sparse, output must be sparse — fewer accurate items is correct.
- CRITICAL severity = confirmed C2/exfil/breach only. Never inflate.
- MITRE: use sub-technique specificity (T1003.001 not T1003). Only map what the enrichment data directly supports. Empty array if nothing supports a mapping.
- Queries: syntactically correct, copy-pasteable, using the exact IOC value from input. No placeholder values. No generic templates.
- Actor attribution only if explicitly named in the enrichment data.
- Respond ONLY with a valid JSON object — no markdown, no prose, no code fences.`;

const AI_PROVIDERS = {
  groq: {
    name: 'Groq',
    hint: 'llama-3.3-70b-versatile · fast + free tier',
    color: '#f97316',
    model: 'llama-3.3-70b-versatile',
    request(prompt) {
      return {
        url: 'https://api.groq.com/openai/v1/chat/completions',
        headers: k => ({ 'Authorization': `Bearer ${k}`, 'Content-Type': 'application/json' }),
        body: {
          model: this.model,
          messages: [
            { role: 'system', content: AI_SYSTEM_PROMPT },
            { role: 'user', content: prompt },
          ],
          max_tokens: 1400,
          temperature: 0.1,
          response_format: { type: 'json_object' },
        },
      };
    },
    parse: d => d.choices?.[0]?.message?.content,
  },
  claude: {
    name: 'Claude',
    hint: 'claude-haiku-4-5 · fast + accurate',
    color: '#d97706',
    model: 'claude-haiku-4-5-20251001',
    request(prompt) {
      return {
        url: 'https://api.anthropic.com/v1/messages',
        headers: k => ({
          'x-api-key': k,
          'anthropic-version': '2023-06-01',
          'anthropic-dangerous-direct-browser-access': 'true',
          'Content-Type': 'application/json',
        }),
        body: {
          model: this.model,
          max_tokens: 1400,
          system: AI_SYSTEM_PROMPT,
          messages: [{ role: 'user', content: prompt }],
        },
      };
    },
    parse: d => d.content?.[0]?.text,
  },
  openai: {
    name: 'OpenAI',
    hint: 'gpt-4o-mini · balanced',
    color: '#10a37f',
    model: 'gpt-4o-mini',
    request(prompt) {
      return {
        url: 'https://api.openai.com/v1/chat/completions',
        headers: k => ({ 'Authorization': `Bearer ${k}`, 'Content-Type': 'application/json' }),
        body: {
          model: this.model,
          messages: [
            { role: 'system', content: AI_SYSTEM_PROMPT },
            { role: 'user', content: prompt },
          ],
          max_tokens: 1400,
          temperature: 0.1,
          response_format: { type: 'json_object' },
        },
      };
    },
    parse: d => d.choices?.[0]?.message?.content,
  },
  gemini: {
    name: 'Gemini',
    hint: 'gemini-2.0-flash · free tier generous',
    color: '#4285f4',
    model: 'gemini-2.0-flash',
    request(prompt) {
      return {
        url: k => `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${k}`,
        headers: () => ({ 'Content-Type': 'application/json' }),
        body: {
          system_instruction: { parts: [{ text: AI_SYSTEM_PROMPT }] },
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: 1400, temperature: 0.1, responseMimeType: 'application/json' },
        },
      };
    },
    parse: d => d.candidates?.[0]?.content?.parts?.[0]?.text,
  },
};

/* ── Key management ──────────────────────────────────────────────────────── */
const aiSaveKey    = (p, k) => k.trim() ? localStorage.setItem(`xv_ai_${p}`, k.trim()) : localStorage.removeItem(`xv_ai_${p}`);
const aiGetKey     = p => localStorage.getItem(`xv_ai_${p}`) || '';
const aiGetProv    = ()  => localStorage.getItem('xv_ai_prov') || 'groq';
const aiSetProv    = p  => localStorage.setItem('xv_ai_prov', p);

/* ── Prompt builder ──────────────────────────────────────────────────────── */
function buildAIPrompt(entry) {
  const { ioc, vt, ab, otx, urlscan, threatfox, urlhaus, mb, ha } = entry;
  const lines = [];

  if (vt && !vt.skipped && !vt.error) {
    const det = `${vt.malicious||0}/${vt.total||0} malicious${vt.suspicious > 0 ? `, ${vt.suspicious} suspicious` : ''}`;
    lines.push(`VirusTotal: ${det}${vt.as_owner ? ` | AS: ${vt.as_owner}` : ''}${vt.country ? ` | Country: ${vt.country}` : ''}${vt.tags?.length ? ` | Tags: ${vt.tags.slice(0,3).join(', ')}` : ''}`);
  }
  if (ab && !ab.skipped && !ab.error)
    lines.push(`AbuseIPDB: ${ab.score}% confidence${ab.totalReports ? ` (${ab.totalReports} reports)` : ''}${ab.isp ? ` | ISP: ${ab.isp}` : ''}${ab.usageType ? ` | Usage: ${ab.usageType}` : ''}${ab.isTor ? ' | TOR exit node' : ''}`);
  if (urlscan && !urlscan.skipped && !urlscan.error && !urlscan.notFound)
    lines.push(`URLScan: ${urlscan.maliciousCount||0}/${urlscan.total} malicious scans`);
  if (mb && !mb.skipped && !mb.error && !mb.notFound)
    lines.push(`MalwareBazaar: ${mb.count} sample${mb.count!==1?'s':''}${mb.families?.length ? ` — families: ${mb.families.slice(0,3).join(', ')}` : ''}`);
  if (otx && !otx.skipped && !otx.error)
    lines.push(`OTX AlienVault: ${otx.pulseCount} pulse${otx.pulseCount!==1?'s':''}${otx.recentPulse ? ` — recent: "${otx.recentPulse}"` : ''}${otx.malwareFamilies?.length ? ` — malware: ${otx.malwareFamilies.slice(0,2).join(', ')}` : ''}${otx.adversaries?.length ? ` — adversaries: ${otx.adversaries.slice(0,2).join(', ')}` : ''}`);
  if (threatfox && !threatfox.skipped && !threatfox.error && !threatfox.notFound)
    lines.push(`ThreatFox: ${threatfox.iocCount} C2 IOC${threatfox.iocCount!==1?'s':''}, confidence ${threatfox.maxConfidence}%${threatfox.malwareFamilies?.length ? ` — ${threatfox.malwareFamilies.slice(0,2).join(', ')}` : ''}${threatfox.firstSeen ? ` — first seen: ${threatfox.firstSeen}` : ''}`);
  if (urlhaus && !urlhaus.skipped && !urlhaus.error && !urlhaus.notFound)
    lines.push(`URLhaus: ${urlhaus.urlsCount} URL${urlhaus.urlsCount!==1?'s':''} listed${urlhaus.threats?.length ? ` — threat: ${urlhaus.threats.join(', ')}` : ''}`);
  if (ha && !ha.skipped && !ha.error && !ha.notFound)
    lines.push(`HybridAnalysis: ${ha.count} sandbox hit${ha.count!==1?'s':''}${ha.verdict ? `, verdict: ${ha.verdict}` : ''}${ha.maxScore ? `, threat score: ${ha.maxScore}/100` : ''}${ha.families?.length ? ` — ${ha.families.slice(0,2).join(', ')}` : ''}`);

  const noData = !lines.length;

  return `Return ONLY a valid JSON object with this structure:
{
  "narrative": "<3 sentences>",
  "mitre": [{"id": "T1234.001", "name": "Technique Name", "tactic": "Tactic"}],
  "queries": {
    "kql": "<KQL — DETECT: alert-specific or HUNT: estate-wide>",
    "spl": "<Splunk SPL>",
    "sigma": "<Sigma YAML>",
    "xql": "<Cortex XDR XQL>"
  }
}

NARRATIVE — exactly 3 sentences:
S1: "VERDICT: [MALICIOUS|SUSPICIOUS|BENIGN|UNKNOWN] — [what this IOC is, one clause]"
S2: [Only numbers and facts from the enrichment below — nothing invented]
S3: "Recommendation: [single concrete action]"

WRITING RULES:
- Only cite sources that appear in the enrichment data with actual values.
- No invented context, no guessed malware families, no assumed attribution.
- No filler: "It is worth noting", "sophisticated", "robust", "leveraging", "concerning", "significant", "in the current threat landscape".
- No over-qualification: "may", "could potentially", "seems to suggest".
- BENIGN: if all sources return clean, say so plainly. Do not dramatize.
- Numbers must match enrichment data exactly.

MITRE: only map techniques the enrichment data directly supports. Use sub-technique IDs (T1078.003). Return empty array if nothing supports a mapping.

QUERIES: use the exact IOC value in each query. DETECT: prefix for alert-triggered queries. HUNT: prefix for estate-wide proactive queries. No placeholder values.

BAD: "This IP exhibits concerning characteristics and may potentially be leveraging sophisticated techniques..."
GOOD: "VERDICT: MALICIOUS — C2 node linked to Qbot. VT: 14/92 engines, AbuseIPDB: 88% (2,341 reports), ThreatFox: 2 C2 IOCs at 100% confidence. Recommendation: Block at firewall, alert on any internal host that reached this IP."

IOC: ${ioc.value}
Type: ${ioc.label}
${noData ? '\nNo enrichment data — mark UNKNOWN, return empty mitre array, still generate syntactically correct queries using the IOC value.' : `\nEnrichment data:\n${lines.join('\n')}`}`;
}

/* ── Call provider ───────────────────────────────────────────────────────── */
async function callAI(provId, key, prompt) {
  const prov = AI_PROVIDERS[provId];
  if (!prov) throw new Error(`Unknown provider: ${provId}`);

  const req    = prov.request(prompt);
  const url    = typeof req.url === 'function' ? req.url(key) : req.url;
  const headers = req.headers(key);

  const resp = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(req.body),
    signal: AbortSignal.timeout(35000),
  });

  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try { const e = await resp.json(); msg = e?.error?.message || e?.message || msg; } catch (_) {}
    throw new Error(msg);
  }

  const data = await resp.json();
  const text = prov.parse(data);
  if (!text) throw new Error('Empty response from provider');
  return text;
}

/* ── Parse AI response ───────────────────────────────────────────────────── */
function parseAIResponse(raw) {
  let text = raw.trim();
  // Strip markdown code fences
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) text = fence[1].trim();
  // Extract JSON object
  const s = text.indexOf('{'), e = text.lastIndexOf('}');
  if (s === -1 || e === -1) throw new Error('No JSON object in response');
  const parsed = JSON.parse(text.slice(s, e + 1));
  return {
    narrative: String(parsed.narrative || ''),
    mitre:     Array.isArray(parsed.mitre) ? parsed.mitre.slice(0, 5) : [],
    queries:   {
      kql:   String(parsed.queries?.kql   || '// No KQL query generated'),
      spl:   String(parsed.queries?.spl   || '// No SPL query generated'),
      sigma: String(parsed.queries?.sigma || '# No Sigma rule generated'),
      xql:   String(parsed.queries?.xql   || '// No XQL query generated'),
    },
  };
}

/* ── Result cache (sessionStorage — survives refresh, keyed by IOC value) ── */
const _aiCache = {
  _k: v => 'xv_ai_r_' + v,
  get(iocValue) {
    try { return JSON.parse(sessionStorage.getItem(this._k(iocValue))); } catch { return null; }
  },
  set(iocValue, result) {
    try { sessionStorage.setItem(this._k(iocValue), JSON.stringify(result)); } catch {}
  },
  clear() {
    Object.keys(sessionStorage).filter(k => k.startsWith('xv_ai_r_')).forEach(k => sessionStorage.removeItem(k));
  },
};

/* ── Tactic color map ────────────────────────────────────────────────────── */
const TACTIC_COLORS = {
  'initial access':        '#f97316',
  'execution':             '#ef4444',
  'persistence':           '#a855f7',
  'privilege escalation':  '#ec4899',
  'defense evasion':       '#6366f1',
  'credential access':     '#f59e0b',
  'discovery':             '#14b8a6',
  'lateral movement':      '#8b5cf6',
  'collection':            '#06b6d4',
  'command and control':   '#FF3B5C',
  'c2':                    '#FF3B5C',
  'exfiltration':          '#f97316',
  'impact':                '#ef4444',
  'reconnaissance':        '#64748b',
  'resource development':  '#64748b',
};
function tacticColor(tactic) {
  const t = (tactic || '').toLowerCase();
  for (const [k, v] of Object.entries(TACTIC_COLORS)) if (t.includes(k)) return v;
  return '#a78bfa';
}

/* ── Report clipboard ────────────────────────────────────────────────────── */
function copyAIReport(iocValue) {
  const cached = _aiCache.get(iocValue);
  if (!cached) return;
  iiClipboard(buildAIReport(cached, iocValue), 'Report copied!');
}

function buildAIReport(result, iocValue) {
  const { narrative, mitre, queries } = result;
  const mitreLines = mitre.length
    ? mitre.map(t => `  ${t.id} · ${t.name} (${t.tactic})`).join('\n')
    : '  None mapped';
  return [
    '=== VERDIKT-AI ANALYSIS ===',
    `IOC: ${iocValue}`,
    '',
    'VERDICT',
    narrative,
    '',
    'MITRE ATT&CK',
    mitreLines,
    '',
    'KQL',
    queries.kql,
    '',
    'SPL',
    queries.spl,
    '',
    'SIGMA',
    queries.sigma,
    '',
    'XQL',
    queries.xql,
  ].join('\n');
}

/* ── Render result HTML ──────────────────────────────────────────────────── */
function renderAIResult(result, uid, iocValue) {
  const { narrative, mitre, queries } = result;
  const provId    = aiGetProv();
  const provName  = AI_PROVIDERS[provId]?.name || 'AI';
  const provColor = AI_PROVIDERS[provId]?.color || '#a78bfa';
  const reportStr = iocValue ? buildAIReport(result, iocValue) : '';

  const mitreHtml = mitre.length
    ? mitre.map(t => {
        const col  = tacticColor(t.tactic);
        const link = t.id ? `https://attack.mitre.org/techniques/${t.id.replace('.','/')}` : '#';
        return `<a class="ai-badge" href="${link}" target="_blank" rel="noopener" style="border-color:${col}40;color:${col};text-decoration:none" title="${escapeHtml(t.tactic || '')}">${escapeHtml(t.id)} · ${escapeHtml(t.name)}</a>`;
      }).join('')
    : '<span class="ai-na">No techniques mapped</span>';

  const tabId     = `ai-q-${uid}`;
  const tabs      = [['kql','KQL'],['spl','SPL'],['sigma','Sigma'],['xql','XQL']];
  const tabsHtml  = tabs.map(([k,l], i) =>
    `<button class="aq-tab${i===0?' active':''}" onclick="switchAITab('${tabId}','${k}',this)">${l}</button>`
  ).join('');
  const blocksHtml = tabs.map(([k], i) =>
    `<div class="ai-query-block" id="${tabId}-${k}"${i>0?' style="display:none"':''}>
      <button class="ai-copy-btn" onclick="iiClipboard(document.getElementById('${tabId}-${k}-pre').textContent,'Copied!')" title="Copy query">COPY</button>
      <pre id="${tabId}-${k}-pre">${escapeHtml(queries[k])}</pre>
    </div>`
  ).join('');

  const escapedIOC = iocValue ? escapeAttr(iocValue) : '';

  return `<div class="ai-panel-inner">
    <div class="ai-panel-meta">
      <span class="ai-prov-badge" style="border-color:${provColor}50;color:${provColor}">via ${escapeHtml(provName)}</span>
      <div style="display:flex;gap:6px">
        ${iocValue ? `<button class="ai-rerun-btn" onclick="copyAIReport('${escapedIOC}')" title="Copy full analysis report">⎘ REPORT</button>` : ''}
        <button class="ai-rerun-btn" onclick="rerunAIPanel('${uid}')" title="Re-analyze">↺ Re-run</button>
      </div>
    </div>
    <div class="ai-section-label">ANALYST NARRATIVE</div>
    <div class="ai-narrative">${escapeHtml(narrative)}</div>
    <div class="ai-section-label">MITRE ATT&amp;CK</div>
    <div class="ai-badges">${mitreHtml}</div>
    <div class="ai-section-label">DETECTION QUERIES</div>
    <div class="ai-query-tabs">${tabsHtml}</div>
    ${blocksHtml}
  </div>`;
}

function switchAITab(uid, tab, btn) {
  ['kql','spl','sigma','xql'].forEach(t => {
    const el = document.getElementById(`${uid}-${t}`);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
  if (btn) {
    const tabs = btn.closest('.ai-query-tabs');
    if (tabs) tabs.querySelectorAll('.aq-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }
}

/* ── Per-row AI toggle ───────────────────────────────────────────────────── */
async function toggleAIPanel(i) {
  const panelRow = document.getElementById(`ai-panel-row-${i}`);
  const btn      = document.getElementById(`ai-btn-${i}`);

  if (panelRow) {
    const isHidden = panelRow.style.display === 'none';
    panelRow.style.display = isHidden ? '' : 'none';
    if (btn) btn.classList.toggle('active', isHidden);
    return;
  }

  const dataRow = document.querySelector(`tr[data-row="${i}"]`);
  if (!dataRow) return;

  const pr = document.createElement('tr');
  pr.id = `ai-panel-row-${i}`;
  pr.className = 'ai-panel-row';
  const td = document.createElement('td');
  td.colSpan = 12;
  td.innerHTML = `<div class="ai-panel" id="ai-panel-${i}"><div class="ai-loading"><div class="vc-spinner"></div><span>Analyzing with AI…</span></div></div>`;
  pr.appendChild(td);
  dataRow.after(pr);
  if (btn) btn.classList.add('active');

  const entry    = scanResults[i];
  const iocValue = entry?.ioc?.value;
  const cached   = iocValue ? _aiCache.get(iocValue) : null;
  if (cached) {
    document.getElementById(`ai-panel-${i}`).innerHTML = renderAIResult(cached, i, iocValue);
    return;
  }
  await _runAnalysis(i, `ai-panel-${i}`);
}

async function rerunAIPanel(uid) {
  const i        = typeof uid === 'number' ? uid : parseInt(uid);
  const entry    = scanResults[i];
  if (entry?.ioc?.value) _aiCache.clear();           // clear only this key
  const panel    = document.getElementById(`ai-panel-${i}`);
  if (panel) {
    panel.innerHTML = `<div class="ai-loading"><div class="vc-spinner"></div><span>Re-analyzing…</span></div>`;
    await _runAnalysis(i, `ai-panel-${i}`);
  }
}

async function _runAnalysis(entryIdx, panelId) {
  const entry    = scanResults[entryIdx];
  const panel    = document.getElementById(panelId);
  if (!entry || !panel) return;

  const iocValue = entry.ioc.value;
  const provId   = aiGetProv();
  const key      = aiGetKey(provId);
  const prov     = AI_PROVIDERS[provId];

  if (!key) {
    panel.innerHTML = `<div class="ai-error">No API key for <strong>${prov?.name || provId}</strong>. <button class="ai-link-btn" onclick="openAISettings()">Open AI Settings →</button></div>`;
    return;
  }

  try {
    const raw    = await callAI(provId, key, buildAIPrompt(entry));
    const result = parseAIResponse(raw);
    _aiCache.set(iocValue, result);
    panel.innerHTML = renderAIResult(result, entryIdx, iocValue);
  } catch (e) {
    panel.innerHTML = `<div class="ai-error"><span>Analysis failed: ${escapeHtml(e.message)}</span> <button class="ai-link-btn" onclick="rerunAIPanel(${entryIdx})">Retry →</button></div>`;
  }
}

/* ── Batch analyze all ───────────────────────────────────────────────────── */
async function analyzeAll() {
  const targets = scanResults.map((r, i) => ({ r, i })).filter(({ r }) => r.done);
  if (!targets.length) { showToast('No completed results to analyze', 'warning'); return; }

  const provId = aiGetProv();
  const key    = aiGetKey(provId);
  if (!key) {
    showToast(`No API key for ${AI_PROVIDERS[provId]?.name || provId} — open AI Settings first`, 'error');
    openAISettings();
    return;
  }

  const batchPanel = document.getElementById('ai-batch-panel');
  if (!batchPanel) return;
  batchPanel.style.display = '';

  const total = targets.length;
  batchPanel.innerHTML = `
    <div class="ai-batch-hdr">
      <div class="ai-batch-title">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="5" stroke="#a78bfa" stroke-width="1.2"/><path d="M6 3.5v2.5l1.8 1.5" stroke="#a78bfa" stroke-width="1.2" stroke-linecap="round"/></svg>
        BATCH AI ANALYSIS
      </div>
      <span class="ai-batch-counter" id="ai-batch-counter">0 / ${total} done</span>
    </div>
    <div id="ai-batch-entries"></div>`;

  const container = document.getElementById('ai-batch-entries');
  let doneCount = 0;

  for (const { r: entry, i } of targets) {
    const iocValue = entry.ioc.value;
    const div = document.createElement('div');
    div.className = 'abe-entry';
    div.id = `abe-${i}`;
    div.innerHTML = `
      <div class="abe-header">
        <span class="abe-dot abe-dot-loading" id="abe-dot-${i}"></span>
        <span class="abe-ioc" title="${escapeHtml(iocValue)}">${escapeHtml(truncate(iocValue, 52))}</span>
        ${TYPE_BADGES[entry.ioc.type] || `<span class="type-badge">${escapeHtml(entry.ioc.label)}</span>`}
      </div>
      <div class="ai-loading" id="abe-body-${i}"><div class="vc-spinner"></div><span>Analyzing…</span></div>`;
    container.appendChild(div);

    try {
      let result = _aiCache.get(iocValue);
      if (!result) {
        const raw = await callAI(provId, key, buildAIPrompt(entry));
        result = parseAIResponse(raw);
        _aiCache.set(iocValue, result);
      }
      const bodyEl = document.getElementById(`abe-body-${i}`);
      if (bodyEl) bodyEl.outerHTML = renderAIResult(result, `b${i}`, iocValue);
      const dot = document.getElementById(`abe-dot-${i}`);
      if (dot) { dot.className = 'abe-dot abe-dot-done'; }
    } catch (e) {
      const bodyEl = document.getElementById(`abe-body-${i}`);
      if (bodyEl) bodyEl.outerHTML = `<div class="ai-error">Failed: ${escapeHtml(e.message)}</div>`;
      const dot = document.getElementById(`abe-dot-${i}`);
      if (dot) { dot.className = 'abe-dot abe-dot-error'; }
    }

    doneCount++;
    const counter = document.getElementById('ai-batch-counter');
    if (counter) counter.textContent = `${doneCount} / ${total} done`;
    if (doneCount < total) await new Promise(res => setTimeout(res, 400));
  }

  showToast(`AI analysis complete — ${total} IOC${total !== 1 ? 's' : ''} analyzed`, 'success');
}

/* ── BYOK Modal ──────────────────────────────────────────────────────────── */
function openAISettings() {
  const modal = document.getElementById('ai-settings-modal');
  if (!modal) return;
  // Populate saved keys
  Object.keys(AI_PROVIDERS).forEach(p => {
    const inp = document.getElementById(`byok-inp-${p}`);
    if (inp) inp.value = aiGetKey(p);
  });
  // Mark active provider
  const active = aiGetProv();
  document.querySelectorAll('.byok-prov-pill').forEach(b =>
    b.classList.toggle('active', b.dataset.prov === active));
  modal.classList.add('open');
}

function closeAISettings(e) {
  if (e && e.target !== document.getElementById('ai-settings-modal')) return;
  document.getElementById('ai-settings-modal')?.classList.remove('open');
}

function saveAIKey(provider) {
  const inp = document.getElementById(`byok-inp-${provider}`);
  if (!inp) return;
  aiSaveKey(provider, inp.value);
  showToast(`${AI_PROVIDERS[provider]?.name || provider} key saved`, 'success');
  updateAIProvIndicator();
}

function clearAIKey(provider) {
  aiSaveKey(provider, '');
  const inp = document.getElementById(`byok-inp-${provider}`);
  if (inp) inp.value = '';
  showToast(`${AI_PROVIDERS[provider]?.name || provider} key cleared`, 'warning');
  updateAIProvIndicator();
}

function selectAIProv(p, btn) {
  aiSetProv(p);
  document.querySelectorAll('.byok-prov-pill').forEach(b =>
    b.classList.toggle('active', b === btn));
  updateAIProvIndicator();
}

/* ── Active provider indicator in hero ───────────────────────────────────── */
function updateAIProvIndicator() {
  const el = document.getElementById('ai-prov-indicator');
  if (!el) return;
  const p      = aiGetProv();
  const prov   = AI_PROVIDERS[p];
  const hasKey = !!aiGetKey(p);
  el.innerHTML = `<span style="color:${hasKey ? prov?.color : 'var(--muted)'}">${prov?.name || p}</span><span class="ai-prov-dot" style="background:${hasKey ? 'var(--accent)' : 'var(--muted)'}"></span>`;
}
document.addEventListener('DOMContentLoaded', updateAIProvIndicator);

function toggleByokKey(provider) {
  const inp = document.getElementById(`byok-inp-${provider}`);
  const btn = document.getElementById(`byok-show-${provider}`);
  if (!inp || !btn) return;
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? 'HIDE' : 'SHOW';
}
