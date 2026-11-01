// Draws /graph/... pages with Pivotick from the JSON at data-source.
(() => {
  'use strict';

  const box = document.getElementById('graph');
  if (!box || typeof window.Pivotick !== 'function') return;

  const show = (id) => {
    const el = document.getElementById(id);
    if (el) el.hidden = false;
  };

  const fail = (msg) => {
    const el = document.getElementById('graph-error');
    if (el) el.textContent = `Graph unavailable: ${msg}`;
    show('graph-error');
  };

  // Node colours are the legend's CSS variables, resolved once.
  const css = getComputedStyle(document.documentElement);
  const color = (name) => css.getPropertyValue(name).trim();

  const type = (n) => (n.kind === 'domain' ? (n.watched ? 'domain-watched' : 'domain') : n.kind);

  const draw = (g) => {
    if (g.excluded_cdn > 0) {
      document.getElementById('graph-cdn-count').textContent = String(g.excluded_cdn);
      show('graph-cdn');
    }
    if (g.truncated) show('graph-truncated');

    const nodes = g.nodes.map((n) => ({
      id: n.id,
      data: { label: n.label, type: type(n), href: n.href, campaign: n.campaign },
    }));
    const edges = g.edges.map((e) => ({
      id: `${e.from}|${e.kind}|${e.to}`,
      from: e.from,
      to: e.to,
      data: { kind: e.kind },
    }));

    new window.Pivotick(box, { nodes, edges }, {
      UI: { mode: 'viewer' },
      // The IIFE build starts its worker from a blob: URL, which the CSP blocks.
      simulation: { useWorker: false },
      render: {
        nodeTypeAccessor: (node) => node.getData().type,
        nodeStyleMap: {
          'domain-watched': { color: color('--graph-domain-watched') },
          domain: { color: color('--graph-domain') },
          ip: { color: color('--graph-ip') },
          nsset: { color: color('--graph-nsset') },
        },
        defaultNodeStyle: {
          text: (node) => node.getData().label,
          textVerticalShift: -1,
          textColor: color('--fg'),
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
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then(draw)
    .catch((err) => fail(err.message));
})();
