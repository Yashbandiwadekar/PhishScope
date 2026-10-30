'use strict';
/* PhishScope front end - plain JavaScript, no libraries, works offline.
   Sections: helpers | router | investigate | monitor | graph | evaluation | rules lab | how it works */

// ------------------------------------------------------------------ helpers
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (k === 'style') e.style.cssText = v; else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const svgns = 'http://www.w3.org/2000/svg';
function sv(tag, attrs = {}, ...kids) {
  const e = document.createElementNS(svgns, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const api = p => fetch(p).then(r => r.json());
const state = { defang: true, rules: null, report: null, mon: null, monFilter: { level: '', src: '', q: '' }, monSort: { k: 'seen', dir: -1 } };
const dfg = s => (state.defang ? String(s).replace(/\./g, '[.]') : String(s));
const pct = (x, d = 1) => (x == null || isNaN(x) ? '-' : (100 * x).toFixed(d) + '%');
const fix = (x, d = 3) => (x == null || isNaN(x) ? '-' : Number(x).toFixed(d));
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const GROUP_CLASS = { name: 'g-name', registry: 'g-registry', dns: 'g-dns', campaign: 'g-campaign', deep: 'g-deep', url: 'g-url' };
const GROUP_OF = id => ({ N: 'name', R: 'registry', D: 'dns', G: 'campaign', C: 'deep', U: 'url' }[id[0]] || 'name');
const levelOf = s => (s >= 50 ? 'HIGH' : s >= 25 ? 'MEDIUM' : 'LOW');
const LEVEL_COLOR = l => css(l === 'HIGH' ? '--high' : l === 'MEDIUM' ? '--med' : '--low');

// ------------------------------------------------------------------ theme + defang
try { const t = localStorage.getItem('ps-theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* storage unavailable */ }
$('#theme').addEventListener('click', () => {
  const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('ps-theme', t); } catch (e) { /* ignore */ }
  rerenderAll();
});
$('#defang').addEventListener('change', e => { state.defang = e.target.checked; rerenderAll(); });
function rerenderAll() {
  if (state.mon) renderMonitor();
  if (G.nodes) drawGraph();
  if (state.report) renderTarget(state.report.target);
  if (loaded.evaluation) renderEvaluation();
  if (loaded.lab) renderLab();
  if (loaded.how) { drawPipe(); }
}

// ------------------------------------------------------------------ router
const TABS = ['investigate', 'monitor', 'graph', 'evaluation', 'lab', 'how'];
const loaded = {};
const init = { monitor: initMonitor, graph: initGraph, evaluation: initEvaluation, lab: initLab, how: initHow };
function route() {
  const tab = TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'investigate';
  TABS.forEach(t => { $('#' + t).hidden = t !== tab; });
  $$('#tabs a').forEach(a => a.classList.toggle('on', a.dataset.tab === tab));
  if (init[tab] && !loaded[tab]) { loaded[tab] = true; init[tab](); }
  if (tab === 'graph' && G.nodes) { resizeGraph(); heat(0.3); }
}
window.addEventListener('hashchange', route);

// ------------------------------------------------------------------ INVESTIGATE
let es = null;
const gaugeArc = (a, b) => {
  const pt = s => { const th = Math.PI * (1 - s / 100); return [110 + 90 * Math.cos(th), 110 - 90 * Math.sin(th)]; };
  const [x1, y1] = pt(a), [x2, y2] = pt(b);
  return `M${x1.toFixed(1)} ${y1.toFixed(1)} A90 90 0 0 1 ${x2.toFixed(1)} ${y2.toFixed(1)}`;
};
$('#gLow').setAttribute('d', gaugeArc(0, 25)); $('#gMed').setAttribute('d', gaugeArc(25, 50)); $('#gHigh').setAttribute('d', gaugeArc(50, 100));
let gScoreNow = 0;
function setGauge(score, animate = true) {
  $('#needle').style.transform = `rotate(${(Math.min(100, score) - 50) * 1.8}deg)`;
  const from = gScoreNow, t0 = performance.now(), dur = animate ? 700 : 1;
  const tick = now => {
    const k = Math.min(1, (now - t0) / dur);
    $('#gScore').textContent = Math.round(from + (score - from) * k);
    if (k < 1) requestAnimationFrame(tick); else gScoreNow = score;
  };
  requestAnimationFrame(tick);
  const lv = levelOf(score), b = $('#gLevel');
  b.textContent = lv; b.className = 'badge ' + lv;
}
function renderTarget(t) {
  $('#tgtLine').textContent = `${dfg(t.host)}  -  registered name ${dfg(t.reg)}` + (t.shared_platform ? '  -  shared platform' : '');
}
async function getRules() { if (!state.rules) state.rules = await api('/api/rules'); return state.rules; }

function resetResult() {
  $('#steps').replaceChildren(); $('#rules').replaceChildren(); $('#stack').replaceChildren(); $('#camp').replaceChildren(); $('#notes').replaceChildren();
  $('#evTabs').replaceChildren(); $('#evBody').replaceChildren(); $('#caveat').textContent = ''; $('#tgtLine').textContent = '';
  gScoreNow = 0; setGauge(0, false); state.report = null; state.fired = [];
}
function investigate(target, deep) {
  if (es) es.close();
  $('#error').hidden = true;
  resetResult();
  $('#result').hidden = false; $('#go').disabled = true;
  const pending = [];
  es = new EventSource(`/api/investigate_stream?target=${encodeURIComponent(target)}&deep=${deep ? 1 : 0}`);
  es.addEventListener('parsed', e => renderTarget(JSON.parse(e.data)));
  es.addEventListener('step_start', e => {
    const d = JSON.parse(e.data);
    $('#steps').append(el('li', { id: 'st-' + d.id }, el('div', { class: 'ic' }, el('div', { class: 'spin' })), el('div', { class: 't' }, el('b', { text: d.label })), el('span', { class: 'ms', text: '...' })));
  });
  es.addEventListener('step_done', e => {
    const d = JSON.parse(e.data), li = $('#st-' + d.id);
    if (!li) return;
    li.querySelector('.ic').replaceChildren(el('span', { class: 'ok', text: '✓' }));
    li.querySelector('.t').append(el('div', { text: d.summary }));
    li.querySelector('.ms').textContent = d.ms + ' ms';
  });
  es.addEventListener('rule', e => pending.push(JSON.parse(e.data)));
  es.addEventListener('fail', e => { const d = JSON.parse(e.data); $('#error').textContent = d.message; $('#error').hidden = false; $('#result').hidden = true; es.close(); $('#go').disabled = false; });
  es.addEventListener('done', async e => {
    es.close(); $('#go').disabled = false;
    const rep = JSON.parse(e.data); state.report = rep;
    await getRules();
    let total = 0;
    pending.forEach((r, i) => setTimeout(() => {
      total = Math.min(100, total + r.points); addRule(r); setGauge(total); updateStack(pending.slice(0, i + 1));
    }, 140 * (i + 1)));
    setTimeout(() => { setGauge(rep.score); finalize(rep); }, 140 * (pending.length + 1) + 150);
    if (!pending.length) finalize(rep);
  });
  es.onerror = () => { if (es.readyState === 2) $('#go').disabled = false; };
}
function addRule(r) {
  $('#rules').append(el('div', { class: 'rule' }, el('div', { class: 'pts ' + GROUP_CLASS[GROUP_OF(r.id)], text: '+' + r.points }),
    el('div', {}, el('div', {}, el('span', { class: 'id', text: r.id }), el('b', { text: r.title }), el('span', { class: 'grp', text: GROUP_OF(r.id) })), el('div', { class: 'muted small', text: r.reason }))));
}
function updateStack(fired) {
  $('#stack').replaceChildren(...fired.map(r => el('i', { style: `width:${r.points}%;background:${css('--' + ({ name: 'accent' }[GROUP_OF(r.id)] || 'accent'))};opacity:${0.5 + 0.5 * Math.random()}`, title: `${r.id} +${r.points}` })));
}
function finalize(rep) {
  $('#caveat').textContent = rep.caveat + ` Analysis took ${rep.seconds} s.`;
  renderEvidence(rep);
  const cm = rep.campaign, camp = $('#camp');
  camp.replaceChildren();
  if (cm.same_ip_known_phishing.length || cm.same_ns_set_known_phishing.length) {
    if (cm.same_ip_known_phishing.length) camp.append(el('p', {}, el('b', { text: 'Same IP as known phishing names: ' }), cm.same_ip_known_phishing.map(dfg).join(', ')));
    if (cm.same_ns_set_known_phishing.length) camp.append(el('p', {}, el('b', { text: 'Same name-server set: ' }), cm.same_ns_set_known_phishing.map(dfg).join(', ')));
  } else camp.append(el('p', { class: 'muted', text: 'No link to known phishing infrastructure in the reference graph.' }));
  $('#notes').replaceChildren(...rep.notes.map(n => el('p', { class: 'muted small', text: 'Note: ' + n })));
  renderRulesAll();
}
function renderRulesAll() {
  if (!state.report) return;
  const firedIds = new Set(state.report.fired_rules.map(r => r.id));
  $$('#rules .rule.off').forEach(n => n.remove());
  if ($('#showAll').checked) for (const r of state.rules) if (!firedIds.has(r.id)) $('#rules').append(el('div', { class: 'rule off' }, el('div', { class: 'pts', text: r.points }),
    el('div', {}, el('div', {}, el('span', { class: 'id', text: r.id }), el('b', { text: r.title }), el('span', { class: 'grp', text: r.group })), el('div', { class: 'muted small', text: r.reason }))));
}
function renderEvidence(rep) {
  const ev = rep.evidence, rows = {};
  const kv = o => o.map(([k, v]) => el('tr', {}, el('th', { text: k }), el('td', { text: v == null || v === '' ? '-' : String(v) })));
  const d = ev.dns || {}, a = ev.asn || {}, r = ev.rdap || {}, i = ev.internetdb || {};
  rows['DNS'] = [['status', d.a_status], ['IP addresses', (d.ips || []).join(', ')], ['name servers', (d.ns || []).join(', ')], ['MX records', d.mx_count], ['SPF', d.has_spf ? 'yes' : 'no'], ['TTL (s)', d.ttl], ['TXT records', d.txt_count],
    ['DMARC', (ev.dnsx || {}).has_dmarc ? 'yes' : 'no'], ['www host', (ev.dnsx || {}).has_www ? 'yes' : 'no'], ['CAA', (ev.dnsx || {}).has_caa ? 'yes' : 'no']];
  rows['Hosting'] = [['AS number', a.asn], ['network', a.as_name], ['country', a.cc], ['prefix', a.prefix], ['registry', a.registry]];
  rows['Registry'] = [['RDAP status', r.status], ['registered', (r.registered || '').slice(0, 10)], ['age (days)', rep.age_days], ['expires', (r.expires || '').slice(0, 10)], ['registrar', r.registrar], ['DNSSEC', r.dnssec ? 'yes' : 'no'], ['status flags', (r.domain_status || []).join(', ')]];
  rows['Shodan'] = [['open ports', (i.ports || []).join(', ')], ['known vulnerabilities', (i.vulns || []).length], ['hostnames on IP', (i.hostnames || []).slice(0, 5).map(dfg).join(', ')], ['tags', (i.tags || []).join(', ')]];
  if (ev.crtsh) rows['Certificates'] = [['status', ev.crtsh.status], ['certificates', ev.crtsh.cert_count], ['first issued', ev.crtsh.first_cert], ['last issued', ev.crtsh.last_cert], ['issuers', (ev.crtsh.issuers || []).join('; ')]];
  if (ev.wayback) rows['Archive'] = [['status', ev.wayback.status], ['archived', String(ev.wayback.archived)], ['first snapshot', ev.wayback.first_snapshot]];
  const tabs = $('#evTabs'), body = $('#evBody'); tabs.replaceChildren();
  const show = k => { $$('button', tabs).forEach(b => b.classList.toggle('on', b.textContent === k)); body.replaceChildren(el('table', {}, kv(rows[k]))); };
  Object.keys(rows).forEach(k => tabs.append(el('button', { text: k, onclick: () => show(k) })));
  show('DNS');
}
$('#form').addEventListener('submit', e => { e.preventDefault(); const t = $('#target').value.trim(); if (t) investigate(t, $('#deep').checked); });
$$('[data-example]').forEach(b => b.addEventListener('click', () => { $('#target').value = b.dataset.example; $('#form').requestSubmit(); }));
$('#sample').addEventListener('click', async () => { const d = await api('/api/sample'); if (d.host) { $('#target').value = dfgAlways(d.host); $('#form').requestSubmit(); } else $('#target').placeholder = 'no live-feed names yet - start the monitor'; });
const dfgAlways = s => String(s).replace(/\./g, '[.]');
$('#showAll').addEventListener('change', renderRulesAll);
$('#exJson').addEventListener('click', () => { if (!state.report) return; const a = el('a', { href: URL.createObjectURL(new Blob([JSON.stringify(state.report, null, 2)], { type: 'application/json' })), download: 'phishscope-report.json' }); a.click(); });
$('#exCopy').addEventListener('click', () => {
  const r = state.report; if (!r) return;
  const txt = `PhishScope: ${dfgAlways(r.target.host)} -> ${r.risk_level} (${r.score}/100)\n` + r.fired_rules.map(f => `  +${f.points} ${f.id} ${f.title}`).join('\n');
  navigator.clipboard && navigator.clipboard.writeText(txt);
});
$('#exPrint').addEventListener('click', () => window.print());

// ------------------------------------------------------------------ MONITOR
function initMonitor() { loadMonitor(); setInterval(() => { if (!$('#monitor').hidden) loadMonitor(); }, 15000); wireMonitorUi(); }
async function loadMonitor() {
  try { state.mon = await api('/api/monitor'); $('#liveTxt').textContent = 'updated ' + new Date().toLocaleTimeString(); renderMonitor(); } catch (e) { $('#liveTxt').textContent = 'offline'; }
}
function wireMonitorUi() {
  const seg = (id, key) => $$('#' + id + ' button').forEach(b => b.addEventListener('click', () => { $$('#' + id + ' button').forEach(x => x.classList.toggle('on', x === b)); state.monFilter[key] = b.dataset.v; renderMonitor(); }));
  seg('mLevel', 'level'); seg('mSrc', 'src');
  $('#mSearch').addEventListener('input', e => { state.monFilter.q = e.target.value.toLowerCase(); renderMonitor(); });
  $$('#mTable th[data-k]').forEach(th => th.addEventListener('click', () => { const k = th.dataset.k; state.monSort = { k, dir: state.monSort.k === k ? -state.monSort.dir : -1 }; renderMonitor(); }));
}
function renderMonitor() {
  const d = state.mon; if (!d) return;
  const s = d.stats, lv = s.levels || {}, src = s.sources || {};
  const fresh = Object.entries(src).filter(([k]) => !k.includes('baseline')).reduce((a, [, v]) => a + v, 0), base = (s.total || 0) - fresh;
  const card = (n, l, c) => el('div', { class: 'stat' }, el('b', { text: n, style: c ? 'color:' + c : '' }), el('span', { text: l }));
  $('#mStats').replaceChildren(card(s.total || 0, 'names scored'), card(lv.HIGH || 0, 'HIGH', css('--high')), card(lv.MEDIUM || 0, 'MEDIUM', css('--med')), card(lv.LOW || 0, 'LOW', css('--low')),
    card(s.latency_mean != null ? s.latency_mean.toFixed(1) + ' s' : '-', 'mean time to verdict'), card(base + ' / ' + fresh, 'baseline / fresh'));
  // timeline
  const tl = d.timeline || [], W = 820, H = 170, pad = 28, bw = Math.max(8, Math.min(60, (W - pad * 2) / Math.max(tl.length, 1) - 8));
  const svg = sv('svg', { viewBox: `0 0 ${W} ${H}` }), mx = Math.max(1, ...tl.map(t => t.n));
  tl.forEach((t, i) => {
    const x = pad + i * ((W - pad * 2) / Math.max(tl.length, 1)), h = (H - 40) * t.n / mx, hh = (H - 40) * t.high / mx, hm = (H - 40) * t.medium / mx;
    svg.append(sv('rect', { x, y: H - 22 - h, width: bw, height: h, fill: css('--low'), opacity: .55 }, sv('title', {}, `${t.t} UTC: ${t.n} names`)));
    svg.append(sv('rect', { x, y: H - 22 - hm - hh, width: bw, height: hm, fill: css('--med') })); svg.append(sv('rect', { x, y: H - 22 - hh, width: bw, height: hh, fill: css('--high') }));
    svg.append(sv('text', { x: x + bw / 2, y: H - 6, 'text-anchor': 'middle', 'font-size': 11, fill: css('--muted') }, t.t));
  });
  $('#mChart').replaceChildren(svg);
  // table
  const f = state.monFilter; let rows = d.rows.filter(r => (!f.level || r.level === f.level) && (!f.src || (f.src === 'baseline' ? r.source.includes('baseline') : !r.source.includes('baseline'))) &&
    (!f.q || r.host.toLowerCase().includes(f.q) || r.rules.some(x => x.toLowerCase() === f.q)));
  const { k, dir } = state.monSort, key = r => (k === 'host' ? r.host : k === 'level' ? ({ HIGH: 3, MEDIUM: 2, LOW: 1 }[r.level]) : k === 'age' ? (r.age == null ? -1 : r.age) : k === 'seen' ? r.seen : r[k]);
  rows = rows.slice().sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * dir);
  const tb = $('#mTable tbody'); tb.replaceChildren();
  rows.slice(0, 250).forEach(r => tb.append(el('tr', { onclick: () => { location.hash = '#investigate'; $('#target').value = dfgAlways(r.host); investigate(r.host, false); } },
    el('td', { text: dfg(r.host) }), el('td', {}, el('span', { class: 'badge ' + r.level, text: r.level })),
    el('td', { class: 'num' }, el('div', { class: 'row', style: 'justify-content:flex-end' }, el('div', { class: 'bar', style: 'width:70px' }, el('i', { style: `width:${r.score}%;background:${LEVEL_COLOR(r.level)}` })), r.score)),
    el('td', {}, r.rules.map(id => el('span', { class: 'rchip', text: id }))), el('td', { class: 'num', text: r.age == null ? '-' : Math.round(r.age) }), el('td', { class: 'num', text: r.latency == null ? '-' : r.latency.toFixed(1) }))));
  $('#mCount').textContent = `Showing ${Math.min(250, rows.length)} of ${rows.length} matching names (click a row to investigate it). Names are defanged by default.`;
}

// ------------------------------------------------------------------ CAMPAIGN GRAPH (hand-written force simulation on canvas)
const G = { nodes: null, edges: null, view: { x: 0, y: 0, k: 1 }, alpha: 1, focus: 0, sel: null, hover: null, drag: null, pan: null, raf: 0 };
async function initGraph() {
  const d = await api('/api/graph');
  G.nodes = d.nodes; G.edges = d.edges; G.clusters = d.clusters;
  const R = 230;
  G.centers = {}; d.clusters.forEach((c, i) => { const a = 2 * Math.PI * i / d.clusters.length; G.centers[c.id] = { x: R * Math.cos(a), y: R * Math.sin(a) }; });
  G.nodes.forEach(n => { const c = G.centers[n.cluster]; n.x = c.x + (Math.random() - .5) * 60; n.y = c.y + (Math.random() - .5) * 60; n.vx = 0; n.vy = 0; n.deg = 0; });
  G.edges.forEach(e => { G.nodes[e.s].deg++; G.nodes[e.t].deg++; });
  const box = $('#gClusters');
  const mk = (id, title, sub, share) => el('div', { class: 'cl' + (G.focus === id ? ' on' : ''), onclick: () => { G.focus = G.focus === id ? 0 : id; initGraphList(); heat(.5); drawGraph(); } },
    el('b', { text: title }), el('div', { class: 'muted small', text: sub }), share == null ? null : el('div', { class: 'bar' }, el('i', { style: `width:${share * 100}%;background:${css('--ph')}` })));
  window.initGraphList = () => { box.replaceChildren(mk(0, 'All clusters', `${G.nodes.length} names`, null), ...G.clusters.map(c => mk(c.id, `Cluster ${c.id}  (${c.size} names)`, `${Math.round(c.share * 100)}% phishing-list names`, c.share))); };
  initGraphList();
  const cv = $('#gCanvas');
  cv.addEventListener('mousedown', gDown); window.addEventListener('mouseup', gUp); cv.addEventListener('mousemove', gMove); cv.addEventListener('wheel', gWheel, { passive: false });
  cv.addEventListener('mouseleave', () => { G.hover = null; $('#gTip').hidden = true; drawGraph(); });
  $('#gBenign').addEventListener('change', () => { heat(.3); drawGraph(); }); $('#gLabels').addEventListener('change', drawGraph);
  $('#gFind').addEventListener('input', e => { const q = e.target.value.toLowerCase().replace(/\[\.\]/g, '.'); if (q.length < 3) return; const n = G.nodes.find(n => n.id.includes(q)); if (n) { select(n); G.view.x = -n.x * G.view.k; G.view.y = -n.y * G.view.k; drawGraph(); } });
  window.addEventListener('resize', () => { if (!$('#graph').hidden) { resizeGraph(); drawGraph(); } });
  resizeGraph(); heat(1);
}
function resizeGraph() { const cv = $('#gCanvas'), r = cv.getBoundingClientRect(), dpr = window.devicePixelRatio || 1; cv.width = r.width * dpr; cv.height = 600 * dpr; G.w = r.width; G.h = 600; G.dpr = dpr; }
const visible = n => $('#gBenign').checked || n.label === 1;
function heat(a) { G.alpha = Math.max(G.alpha, a); if (!G.raf) G.raf = requestAnimationFrame(loop); }
function loop() {
  G.raf = 0;
  if ($('#graph').hidden) return;
  const N = G.nodes, a = G.alpha;
  if (a > 0.015) {
    for (let i = 0; i < N.length; i++) { const p = N[i]; if (!visible(p)) continue;
      for (let j = i + 1; j < N.length; j++) { const q = N[j]; if (!visible(q)) continue;
        let dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy; if (d2 > 14400) continue; if (d2 < 1) { dx = Math.random() - .5; dy = Math.random() - .5; d2 = 1; }
        const f = 520 / d2 * a, d = Math.sqrt(d2); p.vx += dx / d * f; p.vy += dy / d * f; q.vx -= dx / d * f; q.vy -= dy / d * f; } }
    for (const e of G.edges) { const p = N[e.s], q = N[e.t]; if (!visible(p) || !visible(q)) continue; const dx = q.x - p.x, dy = q.y - p.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 26) * 0.012 * Math.min(e.w, 5) * a; p.vx += dx / d * f; p.vy += dy / d * f; q.vx -= dx / d * f; q.vy -= dy / d * f; }
    for (const n of N) { if (!visible(n)) continue; const c = G.centers[n.cluster]; n.vx += (c.x - n.x) * 0.006 * a; n.vy += (c.y - n.y) * 0.006 * a; n.vx *= 0.82; n.vy *= 0.82; if (G.drag !== n) { n.x += n.vx; n.y += n.vy; } }
    G.alpha *= 0.985;
    drawGraph(); G.raf = requestAnimationFrame(loop);
  } else drawGraph();
}
const toScreen = n => [G.w / 2 + G.view.x + n.x * G.view.k, G.h / 2 + G.view.y + n.y * G.view.k];
const toWorld = (sx, sy) => [(sx - G.w / 2 - G.view.x) / G.view.k, (sy - G.h / 2 - G.view.y) / G.view.k];
function drawGraph() {
  if (!G.nodes) return;
  const cv = $('#gCanvas'), c = cv.getContext('2d'); c.setTransform(G.dpr, 0, 0, G.dpr, 0, 0); c.clearRect(0, 0, G.w, G.h);
  const N = G.nodes, ph = css('--ph'), be = css('--be'), dim = G.focus;
  c.lineWidth = 1;
  for (const e of G.edges) { const p = N[e.s], q = N[e.t]; if (!visible(p) || !visible(q)) continue; const [x1, y1] = toScreen(p), [x2, y2] = toScreen(q);
    c.globalAlpha = dim && p.cluster !== dim ? .05 : .45; c.strokeStyle = e.types.includes('ip') ? css('--ip') : css('--ns'); c.lineWidth = Math.min(3, .6 + e.w * .3); c.beginPath(); c.moveTo(x1, y1); c.lineTo(x2, y2); c.stroke(); }
  const labels = $('#gLabels').checked;
  for (const n of N) { if (!visible(n)) continue; const [x, y] = toScreen(n), r = (3 + Math.min(6, Math.sqrt(n.deg))) * Math.min(1.6, Math.max(.7, G.view.k));
    c.globalAlpha = dim && n.cluster !== dim ? .12 : 1; c.fillStyle = n.label ? ph : be; c.beginPath(); c.arc(x, y, r, 0, 7); c.fill();
    if (n === G.sel || n === G.hover) { c.strokeStyle = css('--fg'); c.lineWidth = 2; c.stroke(); }
    if ((labels || n === G.sel || n === G.hover) && (!dim || n.cluster === dim)) { c.globalAlpha = 1; c.fillStyle = css('--fg'); c.font = '11px sans-serif'; c.fillText(dfg(n.id), x + r + 3, y + 3); } }
  c.globalAlpha = 1;
}
function pick(sx, sy) { const [wx, wy] = toWorld(sx, sy); let best = null, bd = 1e9; for (const n of G.nodes) { if (!visible(n)) continue; const dx = n.x - wx, dy = n.y - wy, d = dx * dx + dy * dy; if (d < bd) { bd = d; best = n; } } return best && Math.sqrt(bd) * G.view.k < 12 ? best : null; }
function cvPos(e) { const r = $('#gCanvas').getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; }
function gDown(e) { const [sx, sy] = cvPos(e), n = pick(sx, sy); G.moved = false; if (n) { G.drag = n; } else G.pan = { sx, sy, vx: G.view.x, vy: G.view.y }; $('#gCanvas').style.cursor = 'grabbing'; }
function gMove(e) {
  const [sx, sy] = cvPos(e);
  if (G.drag) { const [wx, wy] = toWorld(sx, sy); G.drag.x = wx; G.drag.y = wy; G.moved = true; heat(.25); drawGraph(); return; }
  if (G.pan) { G.view.x = G.pan.vx + sx - G.pan.sx; G.view.y = G.pan.vy + sy - G.pan.sy; G.moved = true; drawGraph(); return; }
  const n = pick(sx, sy); if (n !== G.hover) { G.hover = n; drawGraph(); }
  const tip = $('#gTip'); if (n) { tip.hidden = false; tip.style.left = sx + 14 + 'px'; tip.style.top = sy + 10 + 'px'; tip.textContent = `${dfg(n.id)}  -  ${n.label ? 'phishing list' : 'benign'}  -  cluster ${n.cluster}`; } else tip.hidden = true;
}
function gUp() { if (G.drag && !G.moved) select(G.drag); if (!G.drag && !G.moved && G.pan) { /* click on empty space */ } G.drag = null; G.pan = null; if ($('#gCanvas')) $('#gCanvas').style.cursor = 'grab'; }
function gWheel(e) { e.preventDefault(); const [sx, sy] = cvPos(e), [wx, wy] = toWorld(sx, sy), k = Math.min(5, Math.max(.3, G.view.k * (e.deltaY < 0 ? 1.12 : .89))); G.view.k = k; G.view.x = sx - G.w / 2 - wx * k; G.view.y = sy - G.h / 2 - wy * k; drawGraph(); }
function select(n) {
  G.sel = n; drawGraph();
  const info = $('#gInfo'); info.replaceChildren(el('b', { text: dfg(n.id) }), el('div', { text: (n.label ? 'on the phishing lists' : 'benign (Tranco)') + ' - cluster ' + n.cluster }),
    el('div', { text: 'IPs: ' + (n.ips.join(', ') || '-') }), el('div', { text: 'name servers: ' + (n.ns.join(', ') || '-') }), el('div', { text: 'registrar: ' + (n.registrar || '-') }), el('div', { text: 'links in graph: ' + n.deg }),
    el('button', { class: 'chip', text: 'Investigate this name', onclick: () => { location.hash = '#investigate'; $('#target').value = dfgAlways(n.id); investigate(n.id, false); } }));
}

// ------------------------------------------------------------------ EVALUATION
let EV = null, evSet = 0, evPrev = 50;
async function initEvaluation() { EV = await api('/api/results'); renderEvaluation(); }
function hbar(host, items, opt = {}) {
  const W = 560, rowH = 30, left = opt.left || 230, H = items.length * rowH + 24, min = opt.min ?? 0, max = opt.max ?? 1, svg = sv('svg', { viewBox: `0 0 ${W} ${H}` });
  const x = v => left + (W - left - 50) * (v - min) / (max - min);
  [0.5, 0.6, 0.7, 0.8, 0.9, 1].filter(v => v >= min && v <= max).forEach(v => { svg.append(sv('line', { x1: x(v), x2: x(v), y1: 4, y2: H - 18, stroke: css('--line') }), sv('text', { x: x(v), y: H - 4, 'text-anchor': 'middle', 'font-size': 10, fill: css('--muted') }, v)); });
  items.forEach((it, i) => { const y = 8 + i * rowH;
    svg.append(sv('text', { x: left - 8, y: y + 14, 'text-anchor': 'end', 'font-size': 12, fill: css('--fg') }, it.label));
    svg.append(sv('rect', { x: left, y, width: Math.max(2, x(it.v) - left), height: 18, rx: 4, fill: it.color || css('--accent') }, sv('title', {}, it.tip || `${it.label}: ${fix(it.v)}`)));
    if (it.sd) svg.append(sv('line', { x1: x(it.v - it.sd), x2: x(it.v + it.sd), y1: y + 9, y2: y + 9, stroke: css('--fg'), 'stroke-width': 1.5 }));
    svg.append(sv('text', { x: x(it.v) + 6, y: y + 13, 'font-size': 11, fill: css('--fg') }, fix(it.v))); });
  host.replaceChildren(svg);
}
function renderEvaluation() {
  if (!EV) return;
  const R = EV.rules, M = EV.enriched, L = EV.lexical, D = EV.dataset, GS = EV.graph_specific, GA = EV.graph;
  const stat = (n, l) => el('div', { class: 'stat' }, el('b', { text: n }), el('span', { text: l }));
  $('#eCards').replaceChildren(stat(D.corpus_rows.toLocaleString(), 'names in the lexical corpus'), stat(D.phishdb_own_registered_unique_names.toLocaleString(), 'unique phishing-list names'),
    stat(pct(M.dns_resolves_by_class.phishing, 0) + ' vs ' + pct(M.dns_resolves_by_class.benign, 0), 'still resolve: phishing vs benign'), stat(pct(M.rdap_not_found_by_class_before_filter.phishing, 0), 'phishing names already deleted'),
    stat(R.rule_firing_table.length, 'rules (weights fixed a priori)'), stat(R.cross_feed_openphish_live.positives, 'live OpenPhish test positives'));
  const mlc = css('--ns'), rc = css('--accent');
  hbar($('#eAuc'), [{ label: 'ML - names only (grouped test)', v: L.final_model.template_grouped_test.roc_auc, color: mlc }, { label: 'ML - all lookups (CV)', v: M.B_ablation_cv['All features'].auc_mean, color: mlc },
    { label: 'ML - all lookups, OpenPhish', v: M.C_cross_feed_enriched.roc_auc, color: mlc }, { label: 'Rules - names only (100k)', v: R.corpus_name_rules.roc_auc, color: rc }, { label: 'Rules - live Phishing.Database', v: R.subset_live_names.roc_auc, color: rc },
    { label: 'Rules - live OpenPhish', v: R.cross_feed_openphish_live.roc_auc, color: rc }], { min: .5, max: 1, left: 215 });
  const abl = Object.entries(M.B_ablation_cv).map(([k, v]) => ({ label: k, v: v.auc_mean, sd: v.auc_sd, tip: `${k}: AUC ${fix(v.auc_mean)} (sd ${fix(v.auc_sd)}), recall at 1% false alarms ${pct(v.tpr_at_fpr_1pct)}` }));
  hbar($('#eAbl'), abl, { min: .5, max: 1, left: 195 });
  // operating points
  const sets = [['Name rules, 100k corpus', R.corpus_name_rules], ['Live Phishing.Database names', R.subset_live_names], ['OpenPhish live (unseen feed)', R.cross_feed_openphish_live]];
  const seg = $('#eSet'); seg.replaceChildren(...sets.map((s, i) => el('button', { class: i === evSet ? 'on' : '', text: s[0], onclick: () => { evSet = i; renderEvaluation(); } })));
  const cur = sets[evSet][1], lv = cur.levels;
  const tbl = el('table', {}, el('thead', {}, el('tr', {}, ...['Level', 'Recall (caught)', 'False-alarm rate', 'Precision here', 'tp / fp / fn / tn'].map(h => el('th', { text: h })))),
    el('tbody', {}, ...Object.entries(lv).map(([k, v]) => el('tr', {}, el('td', { text: k }), el('td', { text: `${pct(v.recall)}  [${pct(v.recall_ci95[0], 0)}-${pct(v.recall_ci95[1], 0)}]` }), el('td', { text: `${pct(v.fpr)}  [${pct(v.fpr_ci95[0], 1)}-${pct(v.fpr_ci95[1], 1)}]` }), el('td', { text: pct(v.precision) }), el('td', { text: `${v.tp} / ${v.fp} / ${v.fn} / ${v.tn}` })))));
  const npos = cur.positives ?? Math.round(cur.n / 2);
  $('#eOp').replaceChildren(tbl, el('p', { class: 'muted small', text: `${cur.n.toLocaleString()} names, ${npos.toLocaleString()} phishing (${pct(npos / cur.n, 1)}). Brackets are 95% Wilson intervals. Precision depends on that share of phishing, which is far higher than in real traffic - see the base-rate explorer.` }));
  const pi = Math.pow(10, -3 + 2.7 * evPrev / 100); $('#ePrev').value = evPrev; $('#ePrevTxt').textContent = (pi * 100).toFixed(pi < .01 ? 2 : 1) + '% of names are phishing';
  $('#ePrec').replaceChildren(...Object.entries(lv).map(([k, v]) => { const p = v.recall * pi / (v.recall * pi + v.fpr * (1 - pi)); return stat(isNaN(p) ? '-' : pct(p, 1), `of ${k.split(' ')[0]} alerts are genuine`); }));
  // rule firing
  const rf = R.rule_firing_table.slice().sort((a, b) => b.fires_on_phishing - a.fires_on_phishing).filter(r => r.fires_on_phishing > 0 || r.fires_on_benign > 0), H = rf.length * 30 + 20, left = 215, W = 560;
  const svg = sv('svg', { viewBox: `0 0 ${W} ${H}` }), mx = Math.max(...rf.map(r => Math.max(r.fires_on_phishing, r.fires_on_benign)), .1);
  rf.forEach((r, i) => { const y = 6 + i * 30;
    svg.append(sv('text', { x: left - 8, y: y + 14, 'text-anchor': 'end', 'font-size': 11.5, fill: css('--fg') }, `${r.rule}  ${r.title.slice(0, 30)}`));
    svg.append(sv('rect', { x: left, y, width: Math.max(1, (W - left - 60) * r.fires_on_phishing / mx), height: 11, fill: css('--ph'), rx: 3 }, sv('title', {}, `fires on ${pct(r.fires_on_phishing)} of phishing, ${pct(r.fires_on_benign)} of benign (lift ${r.lift === null || r.lift === Infinity ? 'inf' : r.lift.toFixed(2)})`)));
    svg.append(sv('rect', { x: left, y: y + 12, width: Math.max(1, (W - left - 60) * r.fires_on_benign / mx), height: 11, fill: css('--be'), rx: 3 }));
    svg.append(sv('text', { x: left + (W - left - 60) * Math.max(r.fires_on_phishing, r.fires_on_benign) / mx + 6, y: y + 14, 'font-size': 10.5, fill: css('--muted') }, `${pct(r.fires_on_phishing, 0)} / ${pct(r.fires_on_benign, 0)}`)); });
  $('#eRules').replaceChildren(svg);
  // graph
  const sig = GA.share_of_names_linked_by_signal, names = { ip: 'same IP', prefix24: 'same /24', nsset: 'name-server set', bulkreg: 'bulk registration' };
  const gs = sv('svg', { viewBox: '0 0 560 190' }), keys = Object.keys(sig);
  keys.forEach((k, i) => { const x = 40 + i * 130; const hp = 120 * sig[k].phishing / .6, hb = 120 * sig[k].benign / .6;
    gs.append(sv('rect', { x, y: 150 - hp, width: 40, height: hp, fill: css('--ph'), rx: 3 }, sv('title', {}, `${names[k]}: ${pct(sig[k].phishing)} of phishing names`)), sv('rect', { x: x + 44, y: 150 - hb, width: 40, height: hb, fill: css('--be'), rx: 3 }, sv('title', {}, `${names[k]}: ${pct(sig[k].benign)} of benign names`)),
      sv('text', { x: x + 42, y: 168, 'text-anchor': 'middle', 'font-size': 11, fill: css('--fg') }, names[k]), sv('text', { x: x + 20, y: 144 - hp, 'text-anchor': 'middle', 'font-size': 10, fill: css('--muted') }, pct(sig[k].phishing, 0)), sv('text', { x: x + 64, y: 144 - hb, 'text-anchor': 'middle', 'font-size': 10, fill: css('--muted') }, pct(sig[k].benign, 0))); });
  $('#eGraph').replaceChildren(gs);
  $('#eGraphTxt').textContent = `With all four signals the clusters show no overall enrichment (likelihood ratio ${GA.likelihood_ratio_phishing_vs_benign_in_clusters.toFixed(2)}). Keeping only the two signals that separated the classes (IP and name-server set): phishing share inside clusters ${pct(GS.phishing_share_inside_clusters, 0)} vs ${pct(GS.baseline_phishing_share_in_sample, 0)} baseline (likelihood ratio ${GS.likelihood_ratio_phishing_vs_benign_in_clusters.toFixed(2)}); ${pct(GS.pure_phishing_clusters_share, 0)} of clusters are at least 90% phishing.`;
  // lessons
  const ag = M.B_age_bands || {};
  $('#eLessons').replaceChildren(...[
    `The Phishing.Database snapshot is stale: only ${pct(M.dns_resolves_by_class.phishing, 0)} of sampled phishing names still resolve (benign: ${pct(M.dns_resolves_by_class.benign, 0)}), and ${pct(M.rdap_not_found_by_class_before_filter.phishing, 0)} are already deleted from the registry. Deleted names are excluded: their absence is a consequence of the takedown, not a property visible at detection time.`,
    `Names that survive takedown are often compromised older sites, so registration-age rules do not separate the classes on this snapshot (AUC of the registry rule group ${fix(R.subset_rule_group_auc.registry, 2)}). On fresh listings the age rules behave differently - see the live monitor.`,
    `Tranco lists registered names while phishing feeds list full host names with subdomains; counting dots alone would "win". Both classes are therefore compared at the registered-name level, and shared-platform names are evaluated separately (rule recall there: ${pct(R.shared_platform_phishing_name_rules.recall_medium_plus, 0)} at MEDIUM+).`,
    `HIGH alerts are precise but rare; MEDIUM+ catches more but raises more false alarms. At realistic prevalence most alerts would be false - use the slider above (Axelsson, 2000).`,
    `A hand-set rule engine is weaker than a trained model on the old snapshot (AUC ${fix(R.subset_live_names.roc_auc, 2)} vs ${fix(M.B_ablation_cv['All features'].auc_mean, 2)}) but is fully explainable and held up better on the unseen OpenPhish feed (${fix(R.cross_feed_openphish_live.roc_auc, 2)} vs ${fix(M.C_cross_feed_enriched.roc_auc, 2)}).`,
    `URLhaus malware hosts were scored too: the rules flag ${pct(R.urlhaus_malware_live.recall_medium_plus, 0)} at MEDIUM+, so the system is a phishing screener, not a general malware detector.`].map(t => el('li', { text: t })));
}
$('#ePrev').addEventListener('input', e => { evPrev = +e.target.value; renderEvaluation(); });

// ------------------------------------------------------------------ RULES LAB
const LAB = { data: null, w: [], set: 0, med: 25, high: 50, base: [] };
async function initLab() { LAB.data = await api('/api/ruleslab'); LAB.base = LAB.data.rules.map(r => r.points); LAB.w = LAB.base.slice(); LAB.med = LAB.data.levels.medium; LAB.high = LAB.data.levels.high; buildLab(); renderLab(); }
function buildLab() {
  const box = $('#lSliders'); box.replaceChildren();
  LAB.data.rules.forEach((r, i) => { const v = el('span', { class: 'v', text: LAB.w[i] });
    const inp = el('input', { type: 'range', min: 0, max: 40, value: LAB.w[i] }); inp.addEventListener('input', () => { LAB.w[i] = +inp.value; v.textContent = inp.value; v.style.color = LAB.w[i] !== LAB.base[i] ? css('--accent') : ''; renderLab(); });
    box.append(el('div', { class: 'sl' }, el('label', { text: `${r.id}  ${r.title}` }), v, inp)); });
  $('#lMed').value = LAB.med; $('#lHigh').value = LAB.high;
  $('#lMed').oninput = e => { LAB.med = +e.target.value; renderLab(); }; $('#lHigh').oninput = e => { LAB.high = +e.target.value; renderLab(); };
  $('#lReset').onclick = () => { LAB.w = LAB.base.slice(); LAB.med = 25; LAB.high = 50; buildLab(); renderLab(); };
  const names = Object.keys(LAB.data.datasets); $('#lSet').replaceChildren(...names.map((n, i) => el('button', { class: i === LAB.set ? 'on' : '', text: n, onclick: () => { LAB.set = i; buildLabSet(); renderLab(); } })));
}
function buildLabSet() { $$('#lSet button').forEach((b, i) => b.classList.toggle('on', i === LAB.set)); }
function aucOf(scores, labels) {
  const idx = scores.map((s, i) => i).sort((a, b) => scores[a] - scores[b]); const ranks = new Array(scores.length); let i = 0;
  while (i < idx.length) { let j = i; while (j + 1 < idx.length && scores[idx[j + 1]] === scores[idx[i]]) j++; const r = (i + j) / 2 + 1; for (let k = i; k <= j; k++) ranks[idx[k]] = r; i = j + 1; }
  let np = 0, sr = 0; labels.forEach((l, k) => { if (l) { np++; sr += ranks[k]; } }); const nn = labels.length - np; return (sr - np * (np + 1) / 2) / (np * nn);
}
function renderLab() {
  if (!LAB.data) return;
  $('#lMedV').textContent = LAB.med; $('#lHighV').textContent = LAB.high;
  const ds = Object.values(LAB.data.datasets)[LAB.set], sc = ds.fired.map(f => Math.min(100, f.reduce((a, j) => a + LAB.w[j], 0))), y = ds.labels;
  const auc = aucOf(sc, y), np = y.reduce((a, b) => a + b, 0), nn = y.length - np;
  const at = th => { let tp = 0, fp = 0; sc.forEach((s, i) => { if (s >= th) { if (y[i]) tp++; else fp++; } }); return { r: tp / np, f: fp / nn, p: tp / Math.max(1, tp + fp) }; };
  const m = at(LAB.med), h = at(LAB.high), card = (n, l, c) => el('div', { class: 'stat' }, el('b', { text: n, style: c ? 'color:' + c : '' }), el('span', { text: l }));
  $('#lStats').replaceChildren(card(fix(auc), 'ROC-AUC'), card(pct(m.r), 'MEDIUM+ catches', css('--med')), card(pct(m.f), 'MEDIUM+ false alarms', css('--med')), card(pct(h.r), 'HIGH catches', css('--high')), card(pct(h.f), 'HIGH false alarms', css('--high')), card(pct(h.p, 0), 'HIGH precision here'));
  const W = 420, H = 230, svg = sv('svg', { viewBox: `0 0 ${W} ${H}` }), bins = 20, cnt = [new Array(bins).fill(0), new Array(bins).fill(0)];
  sc.forEach((s, i) => { cnt[y[i]][Math.min(bins - 1, Math.floor(s / 5))]++; }); const mx = Math.max(...cnt[0].map(v => v / nn), ...cnt[1].map(v => v / np), 1e-6), bw = (W - 40) / bins;
  for (let b = 0; b < bins; b++) { [[0, css('--be')], [1, css('--ph')]].forEach(([c, col]) => { const v = cnt[c][b] / (c ? np : nn), hgt = (H - 40) * v / mx; svg.append(sv('rect', { x: 30 + b * bw + c * bw / 2, y: H - 24 - hgt, width: bw / 2 - 1, height: hgt, fill: col, opacity: .85 })); }); }
  [[LAB.med, css('--med')], [LAB.high, css('--high')]].forEach(([t, col]) => svg.append(sv('line', { x1: 30 + t / 100 * (W - 40), x2: 30 + t / 100 * (W - 40), y1: 4, y2: H - 24, stroke: col, 'stroke-dasharray': '4 3', 'stroke-width': 1.5 })));
  svg.append(sv('text', { x: 30, y: H - 6, 'font-size': 10, fill: css('--muted') }, '0'), sv('text', { x: W - 10, y: H - 6, 'text-anchor': 'end', 'font-size': 10, fill: css('--muted') }, '100 points'));
  $('#lHist').replaceChildren(svg);
  // ROC
  const ths = [...new Set(sc)].sort((a, b) => b - a), pts = [[0, 0]]; ths.forEach(t => { const o = at(t); pts.push([o.f, o.r]); }); pts.push([1, 1]);
  const S = 230, r = sv('svg', { viewBox: `0 0 ${S + 50} ${S + 30}` }), px = v => 30 + v * S, py = v => 6 + (1 - v) * S;
  r.append(sv('rect', { x: 30, y: 6, width: S, height: S, fill: 'none', stroke: css('--line') }), sv('line', { x1: px(0), y1: py(0), x2: px(1), y2: py(1), stroke: css('--line'), 'stroke-dasharray': '3 3' }),
    sv('polyline', { points: pts.map(p => `${px(p[0])},${py(p[1])}`).join(' '), fill: 'none', stroke: css('--accent'), 'stroke-width': 2 }));
  [[m, css('--med'), 'MEDIUM'], [h, css('--high'), 'HIGH']].forEach(([o, col, nm]) => r.append(sv('circle', { cx: px(o.f), cy: py(o.r), r: 5, fill: col }, sv('title', {}, `${nm}: catches ${pct(o.r)}, false alarms ${pct(o.f)}`))));
  r.append(sv('text', { x: 30 + S / 2, y: S + 24, 'text-anchor': 'middle', 'font-size': 10, fill: css('--muted') }, 'false-alarm rate'), sv('text', { x: 8, y: 6 + S / 2, 'font-size': 10, fill: css('--muted'), transform: `rotate(-90 8 ${6 + S / 2})`, 'text-anchor': 'middle' }, 'caught'));
  $('#lRoc').replaceChildren(r);
}

// ------------------------------------------------------------------ HOW IT WORKS
// Same banded layout as the architecture figure in the report (make_figures.py). Every edge is routed by hand along the
// gaps between bands and columns, so no line passes through a box or a band label.
const PW = 200, PH = 66, PC = [50, 285, 520, 755], PT = [52, 198, 344, 490];
const BANDS = ['1  PUBLIC DATA', '2  COLLECTION', '3  ANALYSIS', '4  OUTPUTS'];
const COMP = [
  { id: 'F1', b: 0, c: 0, t: 'Phishing feeds', s: 'four public feeds', files: ['collect_raw.py', 'monitor.py'], txt: 'Phishing.Database (MIT licence), the OpenPhish community feed, PhishStats and URLhaus. Snapshots are downloaded once and hashed in a manifest; the live monitor polls the feeds every ten minutes. Only the feed servers are contacted - a listed domain is never visited.' },
  { id: 'F2', b: 0, c: 1, t: 'Tranco ranking', s: 'benign reference names', files: ['collect_raw.py'], txt: 'A research top-sites list built to resist manipulation (Le Pochat et al., NDSS 2019). Only deep ranks (beyond 100,000) are used as benign reference names, and the rank itself is never a feature.' },
  { id: 'F3', b: 0, c: 2, t: 'Registries and DNS', s: 'RDAP · DNS · ASN · CT', files: ['collectors.py'], txt: 'Public, passive sources: DNS through public resolvers, RDAP registration data (RFC 9082/9083, bootstrap RFC 9224), Team Cymru IP-to-ASN, Shodan InternetDB, crt.sh certificate transparency and the Internet Archive availability API. No account or key is needed.' },
  { id: 'B', b: 1, c: 0, t: 'Dataset builder', s: 'bias controls', files: ['build_dataset.py'], txt: 'Builds the frozen dataset at the registered-name level for both classes, uses deep Tranco ranks only, separates shared-platform names, removes duplicates and sets aside a cross-feed test set.' },
  { id: 'D', b: 1, c: 1, t: 'Batch enrichment', s: 'thread pool, resumable', files: ['enrich.py', 'enrich_extra.py'], txt: 'Runs the passive collectors over thousands of names with a thread pool and fills the cache; names deleted after takedown are detected here.' },
  { id: 'C', b: 1, c: 2, t: 'Passive collectors', s: 'one function per source', files: ['collectors.py'], txt: 'One function per public source, all passive, with per-registry throttling and back-off when a server asks to slow down. Every answer is stored in the evidence cache.' },
  { id: 'K', b: 1, c: 3, t: 'Evidence cache', s: 'SQLite, every lookup kept', files: ['collectors.py', 'data/processed/cache.db'], txt: 'Stores each lookup with its time and status, so every number in the report can be traced to a stored record and re-runs do not repeat queries. Temporary errors are not cached.' },
  { id: 'E', b: 2, c: 0, t: 'Feature extraction', s: 'name + network', files: ['features.py'], txt: 'Turns a registered name and its cached evidence into numbers: length, digits, entropy, brand similarity, DNS records, hosting network, registry age.' },
  { id: 'G', b: 2, c: 1, t: 'Campaign matcher', s: 'shared IP / name servers', files: ['campaign.py', 'graph_corr.py'], txt: 'Links names that share an IP or a rare name-server set with known phishing names, prunes big shared hosts, and finds communities (Louvain) as candidate campaigns.' },
  { id: 'F', b: 2, c: 2, t: 'Rule engine (core)', s: '21 weighted rules', files: ['rules_engine.py'], txt: 'Each rule has an id, a plain-English reason and points. Score = sum of points of the rules that fire (max 100): LOW below 25, MEDIUM 25-49, HIGH 50+. Points were fixed from security knowledge before evaluation.' },
  { id: 'H', b: 2, c: 3, t: 'Investigation engine', s: 'evidence + verdict', files: ['engine.py'], txt: 'Parses a URL (defanged input accepted), gathers the passive evidence step by step, runs the rules and returns the report; a streaming version powers the live web analysis.' },
  { id: 'ML', b: 3, c: 0, t: 'ML comparison', s: 'not the verdict', files: ['train_lexical.py', 'train_enriched.py'], txt: 'Logistic regression, gradient boosting and character n-grams trained for comparison only, with ablations and a cross-feed test. The verdict never depends on them.' },
  { id: 'J', b: 3, c: 1, t: 'Evaluation', s: 'honest metrics', files: ['evaluate_rules.py', 'evalkit.py', 'eval_fresh.py'], txt: 'Measures the rules on live names, on an unseen feed and on malware hosts, with confidence intervals; compares with the ML models; exports the data behind the Evaluation tab and the Rules lab.' },
  { id: 'M', b: 3, c: 2, t: 'Live monitor', s: 'polls live feeds', files: ['monitor.py'], txt: 'Polls the feeds every ten minutes, scores each new name with the investigation engine and records the processing time and, for PhishStats, the time from listing to verdict. The first poll is the baseline; later arrivals count as fresh.' },
  { id: 'I', b: 3, c: 3, t: 'Interfaces', s: 'CLI · web · JSON API', files: ['phishscope.py', 'webapp.py', 'webapp/'], txt: 'Command-line tool, Flask JSON and streaming API, and this single-page interface. Phishing names are defanged by default.' }];
const PX = (c, f) => PC[c] + f * PW, PTop = b => PT[b], PBot = b => PT[b] + PH, PMid = b => PT[b] + PH / 2;
const EDGES = [
  ['F1', 'B', [[PX(0, .7), PBot(0)], [PX(0, .7), PTop(1)]]],
  ['F2', 'B', [[PX(1, .5), PBot(0)], [PX(1, .5), 150], [PX(0, .85), 150], [PX(0, .85), PTop(1)]]],
  ['F3', 'C', [[PX(2, .5), PBot(0)], [PX(2, .5), PTop(1)]]],
  ['B', 'D', [[PX(0, 1), PMid(1)], [PX(1, 0), PMid(1)]]],
  ['D', 'C', [[PX(1, 1), PMid(1)], [PX(2, 0), PMid(1)]]],
  ['C', 'K', [[PX(2, 1), PMid(1)], [PX(3, 0), PMid(1)]]],
  ['K', 'H', [[PX(3, .5), PBot(1)], [PX(3, .5), PTop(2)]]],
  ['K', 'G', [[PX(3, .5), PBot(1)], [PX(3, .5), 292], [PX(1, .5), 292], [PX(1, .5), PTop(2)]]],
  ['K', 'E', [[PX(3, .5), PBot(1)], [PX(3, .5), 292], [PX(0, .75), 292], [PX(0, .75), PTop(2)]]],
  ['G', 'F', [[PX(1, 1), PMid(2)], [PX(2, 0), PMid(2)]]],
  ['F', 'H', [[PX(2, 1), PMid(2)], [PX(3, 0), PMid(2)]]],
  ['E', 'F', [[PX(0, .85), PBot(2)], [PX(0, .85), 432], [PX(2, .3), 432], [PX(2, .3), PBot(2)]]],
  ['E', 'ML', [[PX(0, .6), PBot(2)], [PX(0, .6), PTop(3)]]],
  ['F', 'J', [[PX(2, .65), PBot(2)], [PX(2, .65), 450], [PX(1, .6), 450], [PX(1, .6), PTop(3)]]],
  ['ML', 'J', [[PX(0, 1), PMid(3)], [PX(1, 0), PMid(3)]]],
  ['H', 'I', [[PX(3, .6), PBot(2)], [PX(3, .6), PTop(3)]]],
  ['M', 'H', [[PX(2, .8), PTop(3)], [PX(2, .8), 440], [PX(3, .3), 440], [PX(3, .3), PBot(2)]]],
  ['F1', 'M', [[PX(0, 0), PMid(0)], [16, PMid(0)], [16, 584], [PX(2, .5), 584], [PX(2, .5), PBot(3)]]],
  ['B', 'J', [[PX(0, 0), PMid(1) + 10], [28, PMid(1) + 10], [28, 574], [PX(1, .4), 574], [PX(1, .4), PBot(3)]]]];
let compSel = 'F';
function initHow() { drawPipe(); showComp(compSel); }
function drawPipe() {
  const svg = $('#pipe'); svg.replaceChildren();
  const mk = (id, col) => sv('marker', { id, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto' }, sv('path', { d: 'M0 0 L10 5 L0 10 z', fill: col }));
  svg.append(sv('defs', {}, mk('arr', css('--muted')), mk('arrOn', css('--accent'))));
  BANDS.forEach((t, b) => svg.append(sv('rect', { class: 'band', x: 38, y: PT[b] - 22, width: 929, height: PH + 30, rx: 10 }), sv('text', { class: 'bandt', x: 46, y: PT[b] - 7 }, t)));
  const on = e => e[0] === compSel || e[1] === compSel;
  [...EDGES.filter(e => !on(e)), ...EDGES.filter(on)].forEach(e => svg.append(sv('path', { class: 'edge' + (on(e) ? ' on' : ''), 'marker-end': `url(#${on(e) ? 'arrOn' : 'arr'})`, d: 'M' + e[2].map(p => p.join(' ')).join(' L') })));
  COMP.forEach(c => { const g = sv('g', { class: `node b${c.b + 1}` + (c.id === compSel ? ' on' : ''), transform: `translate(${PC[c.c]},${PT[c.b]})` }, sv('rect', { width: PW, height: PH, rx: 10 }), sv('text', { x: 14, y: 28, 'font-weight': 600 }, c.t), sv('text', { x: 14, y: 48, class: 'sub' }, c.s));
    g.addEventListener('click', () => { compSel = c.id; drawPipe(); showComp(c.id); }); svg.append(g); });
}
function showComp(id) {
  const c = COMP.find(x => x.id === id), name = i => COMP.find(o => o.id === i).t, by = EDGES.filter(e => e[1] === id).map(e => name(e[0])), to = EDGES.filter(e => e[0] === id).map(e => name(e[1]));
  $('#howInfo').replaceChildren(el('h2', { text: c.t }), el('p', { text: c.txt }), el('div', { class: 'muted small', text: 'Files' }), el('div', {}, c.files.map(f => el('code', { text: f, style: 'margin-right:6px' }))),
    el('div', { class: 'muted small', style: 'margin-top:10px', text: 'Receives from' }), el('ul', {}, (by.length ? by : ['(entry point)']).map(t => el('li', { text: t }))), el('div', { class: 'muted small', text: 'Feeds into' }), el('ul', {}, (to.length ? to : ['(final output)']).map(t => el('li', { text: t }))),
    el('p', { class: 'muted small', text: 'Safety: passive only. No component opens a listed page.' }));
}

// ------------------------------------------------------------------ boot
route();
