// ==UserScript==
// @name         AdGuard Home - Provenance des regles
// @namespace    https://github.com/Aerya/AdGuardFilters-pour-iOS
// @version      0.7.0
// @description  Affiche la/les liste(s) source(s) d'origine pour chaque domaine bloque dans le journal d'AdGuard Home, en interrogeant l'index de provenance (shards JSON).
// @author       Aerya
// @match        http://192.168.0.64/*
// @include      /^https?:\/\/192\.168\.0\.64(:\d+)?\//
// @grant        GM_xmlhttpRequest
// @connect      aerya.github.io
// @run-at       document-idle
// ==/UserScript==

// -------------------------------------------------------------------------
// CONFIGURATION
// -------------------------------------------------------------------------
// BASE_URL : ou sont servis index.json + shards/<n>.json.
//   Par defaut : la GitHub Pages du depot (publiee par le workflow update.yml).
//   Adaptez @connect ci-dessus si vous changez d'hote.
const CONFIG = {
  BASE_URL: 'https://aerya.github.io/AdGuardFilters-pour-iOS/',
  // Selecteur des lignes du journal et de la cellule ou injecter le badge.
  // Ajustez apres inspection si le markup de votre AGH differe (mode DEBUG).
  ROW_SELECTOR: '.logs__row',
  RESPONSE_SELECTOR: '.logs__cell--response',
  MODE: 'tooltip',   // 'tooltip' (survol) | 'badge' (ligne visible) | 'both'
  MAX_CACHE: 4096,   // entrees domaine->sources gardees en RAM (LRU simple)
  LABEL: 'sources',  // prefixe affiche
  DEBUG: false,      // true => logs console pour caler les selecteurs
};

// -------------------------------------------------------------------------
// Hash FNV-1a 32 bits sur UTF-8 (doit correspondre a provenance.py)
// -------------------------------------------------------------------------
function mul32(a, b) {
  a >>>= 0; b >>>= 0;
  const al = a & 0xffff, ah = a >>> 16;
  const low = (al * b) >>> 0;
  const high = ((ah * b) & 0xffff) << 16;
  return (low + high) >>> 0;
}
const FNV_PRIME = 0x01000193;
function fnv1a32(str) {
  const bytes = new TextEncoder().encode(str);
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = mul32(h, FNV_PRIME);
  }
  return h >>> 0;
}

// -------------------------------------------------------------------------
// HTTP (cross-origin via GM_xmlhttpRequest)
// -------------------------------------------------------------------------
function gmGetJson(url) {
  return new Promise((resolve, reject) => {
    GM_xmlhttpRequest({
      method: 'GET',
      url,
      onload: (r) => {
        if (r.status >= 200 && r.status < 300) {
          try { resolve(JSON.parse(r.responseText)); }
          catch (e) { reject(e); }
        } else if (r.status === 404) {
          resolve(null); // shard inexistant = aucun domaine dedans
        } else {
          reject(new Error('HTTP ' + r.status + ' ' + url));
        }
      },
      onerror: () => reject(new Error('Echec requete ' + url)),
    });
  });
}

// -------------------------------------------------------------------------
// Etat / caches
// -------------------------------------------------------------------------
let manifest = null;          // index.json
const shardCache = new Map(); // shardIndex -> Promise<data|null>
const domainCache = new Map();// domaine exact -> [noms de sources] | null (LRU borne)
const matchCache = new Map(); // domaine interroge -> [{domain, names}] (LRU borne)

function cacheGet(domain) {
  if (!domainCache.has(domain)) return undefined;
  const v = domainCache.get(domain);
  domainCache.delete(domain); domainCache.set(domain, v); // refresh LRU
  return v;
}
function cacheSet(domain, value) {
  domainCache.set(domain, value);
  if (domainCache.size > CONFIG.MAX_CACHE) {
    domainCache.delete(domainCache.keys().next().value);
  }
}

async function getManifest() {
  if (manifest) return manifest;
  manifest = await gmGetJson(CONFIG.BASE_URL + 'index.json');
  if (CONFIG.DEBUG) console.log('[provenance] manifeste', manifest);
  return manifest;
}

function getShard(index) {
  if (!shardCache.has(index)) {
    shardCache.set(index, gmGetJson(CONFIG.BASE_URL + 'shards/' + index + '.json'));
  }
  return shardCache.get(index);
}

// Lookup d'un domaine EXACT -> noms de sources (ou null). Mis en cache.
async function lookupOne(domain) {
  const cached = cacheGet(domain);
  if (cached !== undefined) return cached;

  const man = await getManifest();
  if (!man) return null;
  const shard = await getShard(fnv1a32(domain) & (man.num_shards - 1));
  const ids = shard && shard[domain];
  let names = null;
  if (ids && ids.length) {
    const byId = {};
    for (const s of man.sources) byId[s.id] = s.name;
    names = ids.map((id) => byId[id] || ('#' + id));
  }
  cacheSet(domain, names);
  return names;
}

// Domaine + parents : `||parent^` bloque les sous-domaines. Renvoie les
// correspondances [{domain, names}], du plus specifique au plus general.
async function getMatches(domain) {
  if (matchCache.has(domain)) return matchCache.get(domain);
  const labels = domain.split('.');
  const out = [];
  for (let i = 0; i < labels.length - 1; i++) {  // s'arrete au domaine a 2 labels
    const cand = labels.slice(i).join('.');
    const names = await lookupOne(cand);
    if (names && names.length) out.push({ domain: cand, names });
  }
  matchCache.set(domain, out);
  if (matchCache.size > CONFIG.MAX_CACHE) matchCache.delete(matchCache.keys().next().value);
  return out;
}

// Texte affiche. Cas simple (domaine exact) sur une ligne ; sinon une ligne par
// domaine correspondant (exact et/ou parents).
function renderMatches(matches, queryDomain) {
  if (!matches || !matches.length) return null;
  if (matches.length === 1 && matches[0].domain === queryDomain) {
    return CONFIG.LABEL + ' : ' + matches[0].names.join(', ');
  }
  return CONFIG.LABEL + ' :\n' +
    matches.map((m) => '· ' + m.domain + ' : ' + m.names.join(', ')).join('\n');
}

// -------------------------------------------------------------------------
// Annotation du DOM
// -------------------------------------------------------------------------
// Domaine STRICT (ancre) : exclut les IP (TLD alphabetique). On lit la cellule
// du domaine, pas le texte de toute la ligne (qui colle la date et "Type:").
const STRICT_DOMAIN = /^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
function extractDomain(row) {
  // 1) Element avec un attribut title = domaine (le plus fiable).
  for (const el of row.querySelectorAll('[title]')) {
    const t = (el.getAttribute('title') || '').trim().toLowerCase();
    if (STRICT_DOMAIN.test(t)) return t;
  }
  // 2) Sinon, premier element feuille dont le texte est exactement un domaine.
  for (const el of row.querySelectorAll('*')) {
    if (el.children.length === 0) {
      const t = el.textContent.trim().toLowerCase();
      if (STRICT_DOMAIN.test(t)) return t;
    }
  }
  return null;
}

// Tooltip custom (instantane, stylé) via delegation d'evenements : survivant a
// la virtualisation du journal et sans listener par ligne.
let tipEl = null;
function ensureTip() {
  if (!tipEl) {
    tipEl = document.createElement('div');
    tipEl.style.cssText =
      'position:fixed;z-index:99999;pointer-events:none;display:none;' +
      'max-width:380px;padding:6px 9px;border-radius:6px;background:#1f2430;' +
      'color:#cfe0ff;font-size:12px;line-height:1.45;white-space:pre-line;' +
      'box-shadow:0 4px 14px rgba(0,0,0,.45);';
    document.body.appendChild(tipEl);
  }
  return tipEl;
}
function tooltipTextForCell(cell) {
  // Recalcule depuis la ligne + le cache JS (React efface nos attributs DOM).
  const row = cell.closest(CONFIG.ROW_SELECTOR);
  if (!row) return null;
  const domain = extractDomain(row);
  if (!domain) return null;
  return renderMatches(matchCache.get(domain), domain);
}
function setupTooltip() {
  document.addEventListener('mouseover', (e) => {
    const cell = e.target.closest && e.target.closest(CONFIG.RESPONSE_SELECTOR);
    if (!cell) return;
    const text = tooltipTextForCell(cell);
    if (!text) return;
    const t = ensureTip();
    t.textContent = text;
    t.style.display = 'block';
  });
  document.addEventListener('mousemove', (e) => {
    if (tipEl && tipEl.style.display === 'block') {
      tipEl.style.left = (e.clientX + 14) + 'px';
      tipEl.style.top = (e.clientY + 16) + 'px';
    }
  });
  document.addEventListener('mouseout', (e) => {
    const cell = e.target.closest && e.target.closest(CONFIG.RESPONSE_SELECTOR);
    if (cell && tipEl && !cell.contains(e.relatedTarget)) tipEl.style.display = 'none';
  });
}

function makeBadge(text) {
  const span = document.createElement('span');
  span.className = 'provenance-badge';
  span.style.cssText =
    'display:block;margin-top:3px;padding:1px 6px;border-radius:4px;' +
    'background:rgba(120,160,255,.18);color:#9ec1ff;font-size:11px;' +
    'font-weight:500;line-height:1.4;white-space:pre-line;';
  span.textContent = text;
  return span;
}

async function annotateRow(row) {
  if (row.dataset.provenanceDone) return;
  row.dataset.provenanceDone = '1';

  const domain = extractDomain(row);
  if (!domain) return;
  if (CONFIG.DEBUG) console.log('[provenance] domaine', domain);

  try {
    const matches = await getMatches(domain);
    if (!matches.length) return;
    // Cellule de reponse (sous le nom de liste), sinon la ligne entiere.
    const target = row.querySelector(CONFIG.RESPONSE_SELECTOR) || row;
    if (!target.isConnected) return;
    if (CONFIG.MODE === 'tooltip' || CONFIG.MODE === 'both') {
      target.style.cursor = 'help';  // indice ; le texte est lu du cache au survol
    }
    if (CONFIG.MODE === 'badge' || CONFIG.MODE === 'both') {
      if (!target.querySelector('.provenance-badge')) {
        target.appendChild(makeBadge(renderMatches(matches, domain)));
      }
    }
  } catch (e) {
    if (CONFIG.DEBUG) console.warn('[provenance] erreur', domain, e);
    row.dataset.provenanceDone = ''; // autorise un nouvel essai
  }
}

function scanRows() {
  const rows = CONFIG.ROW_SELECTOR
    ? document.querySelectorAll(CONFIG.ROW_SELECTOR)
    : [];
  if (CONFIG.DEBUG) console.log('[provenance] lignes trouvees', rows.length);
  rows.forEach(annotateRow);
}

// Le journal AGH est virtualise : les lignes apparaissent/disparaissent au
// scroll. On re-scanne sur mutation (throttle) tant qu'on est sur la vue logs.
let pending = false;
function scheduleScan() {
  if (pending) return;
  pending = true;
  (window.requestIdleCallback || window.requestAnimationFrame)(() => {
    pending = false;
    if (location.hash.includes('logs')) scanRows();
  });
}

function start() {
  setupTooltip();
  const observer = new MutationObserver(scheduleScan);
  observer.observe(document.body, { childList: true, subtree: true });
  scheduleScan();
  if (CONFIG.DEBUG) console.log('[provenance] demarre, BASE_URL =', CONFIG.BASE_URL);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
