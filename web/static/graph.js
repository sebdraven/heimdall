// Draws /graph/... pages with Pivotick from the JSON at data-source.
(() => {
  'use strict';

  const show = (id) => {
    const el = document.getElementById(id);
    if (el) el.hidden = false;
  };

  const say = (id, msg) => {
    const el = document.getElementById(id);
    if (el) el.textContent = msg;
    show(id);
  };

  const getJSON = (res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const withVT = (on) => {
    const u = new URL(window.location.href);
    if (on) u.searchParams.set('vt', '1');
    else u.searchParams.delete('vt');
    return u.toString();
  };

  const vtControls = () => {
    const toggle = document.getElementById('graph-vt-toggle');
    if (toggle) toggle.addEventListener('change', () => window.location.assign(withVT(toggle.checked)));

    const summary = document.getElementById('graph-vt-summary');
    if (summary && window.heimdallVTJob) {
      window.heimdallVTJob.watch(summary, document.getElementById('graph-vt-enrich'), withVT(true));
    }
  };

  vtControls();

  const box = document.getElementById('graph');
  if (!box || typeof window.Pivotick !== 'function') return;

  const fail = (msg) => say('graph-error', `Graph unavailable: ${msg}`);

  // Node colours are the legend's CSS variables, resolved once.
  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();

  const type = (n) => {
    if (n.source === 'vt') return 'vt';
    return n.kind === 'domain' ? (n.watched ? 'domain-watched' : 'domain') : n.kind;
  };

  const draw = (g) => {
    if (g.excluded_cdn > 0) {
      document.getElementById('graph-cdn-count').textContent = String(g.excluded_cdn);
      show('graph-cdn');
    }
    if (g.truncated) show('graph-truncated');

    const nodes = g.nodes.map((n) => ({
      id: n.id,
      data: { label: n.label, type: type(n), href: n.href, campaign: n.campaign, source: n.source },
    }));
    const edges = g.edges.map((e) => ({
      id: `${e.from}|${e.kind}|${e.to}`,
      from: e.from,
      to: e.to,
      data: { kind: e.kind, first_seen: e.first_seen, last_seen: e.last_seen },
    }));

    new window.Pivotick(box, { nodes, edges }, {
      UI: {
        mode: 'light',
        editors: { nodeCreator: { enabled: false }, edgeCreator: { enabled: false }, nodeEditor: { enabled: false } },
        notes: { enabled: false },
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
          'domain-watched': { color: color('--graph-domain-watched') },
          domain: { color: color('--graph-domain') },
          ip: { color: color('--graph-ip') },
          nsset: { color: color('--graph-nsset') },
          vt: { color: color('--graph-vt-node') },
        },
        defaultNodeStyle: {
          text: (node) => node.getData().label,
          textVerticalShift: -1,
          textColor: color('--fg'),
          textTruncate: false,
        },
        edgeTypeAccessor: (edge) => edge.getData().kind,
        edgeStyleMap: {
          VT: { dashed: true, animateDash: false, strokeColor: color('--graph-vt') },
        },
      },
      callbacks: {
        onNodeClick: (event, node) => {
          const href = node.getData().href;
          if (typeof href === 'string' && href.startsWith('/') && !href.startsWith('//')) {
            window.location.assign(href);
          }
        },
      },
    });
  };

  fetch(box.dataset.source, { headers: { Accept: 'application/json' } })
    .then(getJSON)
    .then(draw)
    .catch((err) => fail(err.message));
})();
