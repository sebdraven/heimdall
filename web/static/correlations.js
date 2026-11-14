// Draws /correlations: the matrix of campaign pairs, the links of a pair,
// the Pivotick graph and the new links, from the JSON of data-source.
(() => {
  'use strict';

  const root = document.getElementById('correlations');
  if (!root) return;

  const $ = (id) => document.getElementById(id);

  const el = (tag, attrs, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'text') n.textContent = v;
      else if (k === 'class') n.className = v;
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const k of kids) if (k !== null && k !== undefined) n.append(k);
    return n;
  };

  const getJSON = (res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const fmtTS = (s) => (s ? s.replace('T', ' ').replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)$/, '') : '—');
  const fmtDay = (s) => (s ? s.slice(0, 10) : '—');
  const pairKey = (a, b) => (a < b ? `${a}-${b}` : `${b}-${a}`);
  const domainLink = (fqdn) => el('a', { href: `/domains/${encodeURIComponent(fqdn)}`, text: fqdn });

  const st = {
    data: null,
    names: new Map(),
    pairs: new Map(),
    pair: null,
    graph: null,
    tab: 'matrix',
  };

  const fail = (msg) => {
    $('cx-error').textContent = msg;
    $('cx-error').hidden = false;
  };

  // filters returns the query of the filters: kinds only when some are off.
  const filters = () => {
    const q = new URLSearchParams();
    const min = Number($('cx-min').value);
    if (min > 0) q.set('min_score', String(Math.min(min, 1)));
    const boxes = [...root.querySelectorAll('input[name="kind"]')];
    const on = boxes.filter((b) => b.checked).map((b) => b.value);
    if (on.length < boxes.length) q.set('kinds', on.join(','));
    return q;
  };

  const withQuery = (base, extra) => {
    const q = filters();
    for (const [k, v] of Object.entries(extra || {})) q.set(k, v);
    const s = q.toString();
    return s ? `${base}?${s}` : base;
  };

  const kindsLabel = (counts) => Object.entries(counts || {}).map(([k, n]) => `${k} ${n}`).join(' · ');

  // Matrix.

  const renderMatrix = () => {
    const table = $('cx-matrix');
    table.replaceChildren();
    const ids = new Set();
    for (const p of st.data.pairs) {
      ids.add(p.a);
      ids.add(p.b);
    }
    const list = [...ids].sort((x, y) => (st.names.get(x) || '').localeCompare(st.names.get(y) || '') || x - y);
    $('cx-empty').hidden = list.length > 0;
    $('cx-empty').textContent = st.data.computed_at ? 'No link between campaigns.' : 'Links not computed yet.';
    if (!list.length) return;
    table.append(el('thead', {}, el('tr', {}, el('th'), ...list.map((id) => el('th', { scope: 'col' },
      el('a', { href: `/campaigns/${id}/analytics`, text: st.names.get(id) || `#${id}` }))))));
    const body = el('tbody');
    for (const a of list) {
      const tr = el('tr', {}, el('th', { scope: 'row', text: st.names.get(a) || `#${a}` }));
      for (const b of list) {
        if (a === b) {
          tr.append(el('td', { class: 'cx-self' }));
          continue;
        }
        const p = st.pairs.get(pairKey(a, b));
        if (!p) {
          tr.append(el('td'));
          continue;
        }
        const td = el('td', {
          class: `cx-s${Math.max(1, Math.ceil(p.score * 10))}`, role: 'button', tabindex: '0',
          'data-pair': pairKey(a, b),
          'aria-label': `${st.names.get(a)} and ${st.names.get(b)}: score ${p.score.toFixed(2)}, ${kindsLabel(p.counts)}`,
        }, el('span', { class: 'cx-score', text: p.score.toFixed(2) }), el('span', { class: 'cx-counts', text: kindsLabel(p.counts) }));
        const open = () => openPair(a, b);
        td.addEventListener('click', open);
        td.addEventListener('keydown', (e) => {
          if (e.key !== 'Enter' && e.key !== ' ') return;
          e.preventDefault();
          open();
        });
        tr.append(td);
      }
      body.append(tr);
    }
    table.append(body);
    markPair();
  };

  const markPair = () => {
    for (const td of root.querySelectorAll('td.cx-on')) td.classList.remove('cx-on');
    if (!st.pair) return;
    for (const td of root.querySelectorAll(`td[data-pair="${pairKey(st.pair[0], st.pair[1])}"]`)) td.classList.add('cx-on');
  };

  // Links of a pair.

  const period = (p) => (p ? `${fmtDay(p.first)} → ${fmtDay(p.last)}` : '—');

  const evidenceTable = (rows) => el('table', {},
    el('thead', {}, el('tr', {}, ...['Weight', 'Kind', 'Value', 'Domain', 'Domain', 'Period', 'First seen', 'Last seen'].map((h) => el('th', { text: h })))),
    el('tbody', {}, ...rows.map((e) => el('tr', {},
      el('td', { text: e.weight.toFixed(4).replace(/0+$/, '').replace(/\.$/, '') }),
      el('td', {}, el('span', { class: `swatch-line cx-line-${e.kind}` }), e.kind),
      el('td', { class: 'cx-value' }, el('code', { text: e.value })),
      el('td', {}, domainLink(e.domain_a)),
      el('td', {}, domainLink(e.domain_b)),
      el('td', { class: 'nowrap', text: period(e.period) }),
      el('td', { class: 'nowrap', text: fmtTS(e.first_seen) }),
      el('td', { class: 'nowrap', text: fmtTS(e.last_seen) })))));

  const pastTable = (rows) => el('table', {},
    el('thead', {}, el('tr', {}, ...['Kind', 'Value', 'Domain', 'Domain', 'First seen', 'Last seen'].map((h) => el('th', { text: h })))),
    el('tbody', {}, ...rows.map((l) => el('tr', {},
      el('td', { text: l.kind }),
      el('td', { class: 'cx-value' }, el('code', { text: l.value })),
      el('td', {}, domainLink(l.domain_a)),
      el('td', {}, domainLink(l.domain_b)),
      el('td', { class: 'nowrap', text: fmtTS(l.first_seen) }),
      el('td', { class: 'nowrap', text: fmtTS(l.last_seen) })))));

  let pairSeq = 0;
  const openPair = (a, b) => {
    st.pair = [a, b];
    markPair();
    const u = new URL(window.location.href);
    u.searchParams.set('a', String(a));
    u.searchParams.set('b', String(b));
    window.history.replaceState(null, '', u);
    const panel = $('cx-pair');
    $('cx-pair-title').textContent = `${st.names.get(a) || `#${a}`} ↔ ${st.names.get(b) || `#${b}`}`;
    $('cx-pair-body').replaceChildren(el('p', { class: 'meta', text: 'Loading…' }));
    panel.hidden = false;
    panel.focus();
    const seq = ++pairSeq;
    fetch(withQuery(`${root.dataset.pair}${a}/${b}/data`), { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((d) => {
        if (seq !== pairSeq) return;
        const out = [
          el('p', {}, el('strong', { text: `score ${d.score.toFixed(2)}` }), ` · ${kindsLabel(d.counts) || 'no current link'}`),
          el('p', { class: 'meta' },
            el('a', { href: `/campaigns/${d.a.id}/analytics`, text: d.a.name }), ' · ',
            el('a', { href: `/campaigns/${d.b.id}/analytics`, text: d.b.name })),
        ];
        out.push(d.evidence.length ? evidenceTable(d.evidence) : el('p', { class: 'empty', text: 'No current link.' }));
        if (d.past.length) out.push(el('h3', { text: 'No longer found' }), pastTable(d.past));
        $('cx-pair-body').replaceChildren(...out);
      })
      .catch((err) => {
        if (seq === pairSeq) $('cx-pair-body').replaceChildren(el('p', { class: 'error', text: `Unavailable: ${err.message}` }));
      });
  };

  const closePair = () => {
    $('cx-pair').hidden = true;
    st.pair = null;
    markPair();
    const u = new URL(window.location.href);
    u.searchParams.delete('a');
    u.searchParams.delete('b');
    window.history.replaceState(null, '', u);
  };

  // New links.

  const renderNew = () => {
    const body = $('cx-new');
    body.replaceChildren();
    if (!st.data.new_links.length) {
      body.append(el('tr', {}, el('td', { colspan: '7', class: 'empty', text: 'No new link.' })));
      return;
    }
    for (const l of st.data.new_links) {
      body.append(el('tr', {},
        el('td', { class: 'nowrap', text: fmtTS(l.first_seen) }),
        el('td', {}, el('span', { class: `swatch-line cx-line-${l.kind}` }), l.kind),
        el('td', { class: 'cx-value' }, el('code', { text: l.value })),
        el('td', {}, domainLink(l.domain_a)),
        el('td', { text: st.names.get(l.campaign_a) || `#${l.campaign_a}` }),
        el('td', {}, domainLink(l.domain_b)),
        el('td', { text: st.names.get(l.campaign_b) || `#${l.campaign_b}` })));
    }
  };

  // Graph.

  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();
  const KINDS = ['cert', 'tracker', 'ns_set', 'ip', 'cname', 'mx', 'soa', 'rdap', 'vt'];
  const DASHED = new Set(['cert', 'vt', 'soa', 'rdap']);

  const nodeType = (n) => {
    if (n.kind === 'campaign') return 'campaign';
    return n.kind === 'domain' ? (n.watched ? 'domain-watched' : 'domain') : n.kind;
  };

  const toNode = (n) => ({ id: n.id, data: { label: n.label, type: nodeType(n), href: n.href } });
  const toEdge = (e) => ({ id: `${e.from}|${e.kind}|${e.to}`, from: e.from, to: e.to, data: { kind: e.kind, from: e.from, to: e.to } });
  const campaignOf = (id) => (typeof id === 'string' && id.startsWith('c:') ? Number(id.slice(2)) : 0);
  const dataOf = (x) => (x && typeof x.getData === 'function' && x.getData()) || {};
  const hrefOf = (node) => {
    const h = dataOf(node).href;
    return typeof h === 'string' && h.startsWith('/') && !h.startsWith('//') ? h : '';
  };

  const nodeMenu = [{
    text: 'Open page',
    title: 'Open the page of this node',
    variant: 'outline-primary',
    visible: (node) => hrefOf(node) !== '',
    onclick: (event, node) => window.location.assign(hrefOf(node)),
  }];

  const edgeStyles = () => {
    const out = { member: { strokeColor: color('--cx-member') } };
    for (const k of KINDS) out[k] = { strokeColor: color(`--cx-${k}`), dashed: DASHED.has(k), animateDash: false };
    return out;
  };

  const drawGraph = (g) => {
    const box = $('cx-graph');
    box.replaceChildren();
    st.graph = null;
    $('cx-graph-truncated').hidden = !g.truncated;
    if (typeof window.Pivotick !== 'function') {
      fail('Graph unavailable: Pivotick not loaded');
      return;
    }
    st.graph = new window.Pivotick(box, { nodes: g.nodes.map(toNode), edges: g.edges.map(toEdge) }, {
      UI: {
        mode: 'light',
        editors: { nodeCreator: { enabled: false }, edgeCreator: { enabled: false }, nodeEditor: { enabled: false } },
        notes: { enabled: false },
        contextMenu: { menuNode: { menu: nodeMenu } },
        simplify: {
          rules: [
            { kind: 'neighbours', enabled: true },
            { kind: 'chains', enabled: false },
            { kind: 'degree', enabled: false },
            { kind: 'kcore', enabled: false },
          ],
        },
      },
      // The IIFE build starts its worker from a blob: URL, which the CSP blocks.
      simulation: { useWorker: false },
      render: {
        nodeTypeAccessor: (node) => node.getData().type,
        nodeStyleMap: {
          campaign: { color: color('--cx-campaign') },
          'domain-watched': { color: color('--graph-domain-watched') },
          domain: { color: color('--graph-domain') },
          ip: { color: color('--graph-ip') },
          nsset: { color: color('--graph-nsset') },
          cert: { color: color('--cx-cert') },
          tracker: { color: color('--cx-tracker') },
          soa: { color: color('--cx-soa') },
          registrar: { color: color('--cx-rdap') },
        },
        defaultNodeStyle: {
          text: (node) => node.getData().label,
          textVerticalShift: -1,
          textColor: color('--fg'),
          textTruncate: false,
        },
        edgeTypeAccessor: (edge) => edge.getData().kind,
        edgeStyleMap: edgeStyles(),
      },
      callbacks: {
        onEdgeClick: (event, edge) => {
          const d = dataOf(edge);
          const a = campaignOf(d.from);
          const b = campaignOf(d.to);
          if (a && b) loadGraph([a, b]);
        },
      },
    });
  };

  let graphSeq = 0;
  const loadGraph = (expand) => {
    const pair = expand || st.pair;
    const note = $('cx-graph-pair');
    note.hidden = !pair;
    if (pair) note.textContent = `${st.names.get(pair[0]) || `#${pair[0]}`} ↔ ${st.names.get(pair[1]) || `#${pair[1]}`}: domains and shared values`;
    const seq = ++graphSeq;
    fetch(withQuery(root.dataset.graph, pair ? { expand: `${pair[0]},${pair[1]}` } : {}), { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((g) => {
        if (seq === graphSeq) drawGraph(g);
      })
      .catch((err) => fail(`Graph unavailable: ${err.message}`));
  };

  const showTab = (tab) => {
    st.tab = tab;
    $('cx-tab-matrix').setAttribute('aria-selected', String(tab === 'matrix'));
    $('cx-tab-graph').setAttribute('aria-selected', String(tab === 'graph'));
    $('cx-matrix-panel').hidden = tab !== 'matrix';
    $('cx-graph-panel').hidden = tab !== 'graph';
    if (tab === 'graph') loadGraph();
  };

  // Loading and controls.

  const load = () => {
    $('cx-error').hidden = true;
    root.setAttribute('aria-busy', 'true');
    fetch(withQuery(root.dataset.source), { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((d) => {
        st.data = d;
        st.names = new Map(d.campaigns.map((c) => [c.id, c.name]));
        st.pairs = new Map(d.pairs.map((p) => [pairKey(p.a, p.b), p]));
        $('cx-computed').textContent = d.computed_at ? `computed ${fmtTS(d.computed_at)} UTC` : 'not computed yet';
        renderMatrix();
        renderNew();
        if (st.tab === 'graph') loadGraph();
        if (st.pair && !$('cx-pair').hidden) openPair(st.pair[0], st.pair[1]);
      })
      .catch((err) => fail(`Correlations unavailable: ${err.message}`))
      .finally(() => root.removeAttribute('aria-busy'));
  };

  const params = new URLSearchParams(window.location.search);
  const a = Number(params.get('a'));
  const b = Number(params.get('b'));

  $('cx-tab-matrix').addEventListener('click', () => showTab('matrix'));
  $('cx-tab-graph').addEventListener('click', () => showTab('graph'));
  // At least one kind stays checked.
  $('cx-filters').addEventListener('change', (e) => {
    const boxes = [...root.querySelectorAll('input[name="kind"]')];
    if (e.target.name === 'kind' && !boxes.some((x) => x.checked)) e.target.checked = true;
    load();
  });
  $('cx-filters').addEventListener('submit', (e) => {
    e.preventDefault();
    load();
  });
  $('cx-pair-close').addEventListener('click', closePair);
  $('cx-pair-graph').addEventListener('click', () => {
    const pair = st.pair;
    if (!pair) return;
    $('cx-pair').hidden = true;
    showTab('graph');
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('cx-pair').hidden) closePair();
  });

  if (a > 0 && b > 0 && a !== b) {
    st.pair = [a, b];
    $('cx-pair').hidden = false;
  }
  load();
})();
