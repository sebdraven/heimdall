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

  const toNode = (n) => ({
    id: n.id,
    data: {
      label: n.label,
      type: type(n),
      href: n.href,
      campaign: n.campaign,
      source: n.source,
      ip: n.kind === 'ip' ? n.id.slice('ip:'.length) : '',
      fqdn: n.kind === 'domain' ? n.id.slice('d:'.length) : '',
    },
  });

  // An edge is unique by (from, kind, to).
  const toEdge = (e) => ({
    id: `${e.from}|${e.kind}|${e.to}`,
    from: e.from,
    to: e.to,
    data: { kind: e.kind, first_seen: e.first_seen, last_seen: e.last_seen },
  });

  const dataOf = (node) => (node && typeof node.getData === 'function' && node.getData()) || {};
  const ipOf = (node) => dataOf(node).ip || '';
  const fqdnOf = (node) => dataOf(node).fqdn || '';
  const hrefOf = (node) => {
    const href = dataOf(node).href;
    return typeof href === 'string' && href.startsWith('/') && !href.startsWith('//') ? href : '';
  };

  const canEnrich = box.dataset.vt === '1' && box.dataset.analyst === '1';
  const pageVT = new URL(box.dataset.source, window.location.href).searchParams.get('vt') === '1';
  const maxExpand = 50;
  const expandedStyle = { strokeWidth: 4, strokeColor: color('--fg') };

  let graph = null;
  const expanded = new Set();
  const pending = new Set();
  // Nodes enriched from their menu: expanding them reads the VirusTotal cache.
  const enriched = new Set();

  const expandStatus = (msg) => {
    const el = document.getElementById('graph-expand');
    if (!el) return;
    el.textContent = msg;
    el.hidden = msg === '';
  };

  // mark adds or removes the border of an expanded node.
  const mark = (node, on) => {
    const style = { ...(node.getStyle() || {}) };
    delete style.strokeWidth;
    delete style.strokeColor;
    node.setStyle(on ? { ...style, ...expandedStyle } : style);
  };

  const expandURL = (node) => {
    let path = '';
    if (ipOf(node)) path = `/graph/ip/${encodeURIComponent(ipOf(node))}/data`;
    else if (fqdnOf(node)) path = `/graph/domain/${encodeURIComponent(fqdnOf(node))}/data`;
    if (path && (pageVT || enriched.has(node.id))) path += '?vt=1';
    return path;
  };

  // around places the i-th of count new nodes on a ring around node.
  const around = (n, node, i, count) => {
    if (typeof node.x !== 'number' || typeof node.y !== 'number') return n;
    const a = (2 * Math.PI * i) / count;
    return { ...n, x: node.x + 60 * Math.cos(a), y: node.y + 60 * Math.sin(a) };
  };

  // expand merges the graph of node into the current one, at most maxExpand
  // new nodes, once per node.
  const expand = (node) => {
    const url = expandURL(node);
    if (!graph || !url || expanded.has(node.id) || pending.has(node.id)) return;
    pending.add(node.id);
    fetch(url, { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((g) => {
        const fresh = g.nodes.filter((n) => !graph.getMutableNode(n.id));
        const added = fresh.slice(0, maxExpand);
        const ids = new Set(added.map((n) => n.id));
        const present = (id) => ids.has(id) || !!graph.getMutableNode(id);
        const edges = g.edges.map(toEdge).filter((e) => present(e.from) && present(e.to) && !graph.getMutableEdge(e.id));
        expanded.add(node.id);
        mark(node, true);
        // An empty update still redraws the border.
        graph.updateData(added.map((n, i) => around(toNode(n), node, i, added.length)), edges);
        if (fresh.length > maxExpand) expandStatus(`+${fresh.length - maxExpand} not shown`);
        else if (added.length === 0) expandStatus('no neighbours');
        else expandStatus('');
      })
      .catch((err) => expandStatus(`Expand failed: ${err.message}`))
      .finally(() => pending.delete(node.id));
  };

  // The status of an enrichment started from a node shows in the graph bar.
  // Once it has finished, the next click expands the node again with the
  // VirusTotal resolutions.
  const enrichNode = (node) => {
    const summary = document.getElementById('graph-vt-summary');
    if (!summary || !window.heimdallVTJob) return;
    const endpoint = ipOf(node)
      ? `/rdata/${encodeURIComponent(ipOf(node))}/vt?depth=1`
      : `/graph/domain/${encodeURIComponent(fqdnOf(node))}/vt?depth=1`;
    window.heimdallVTJob.enrich(summary, endpoint, box.dataset.csrf, () => {
      enriched.add(node.id);
      if (!expanded.delete(node.id) || !graph) return;
      mark(graph.getMutableNode(node.id) || node, false);
      graph.updateData([], []);
    });
  };

  // Node context menu entries: Pivotick appends UI.contextMenu.menuNode.menu
  // to its own and calls visible(node) and onclick(event, node).
  const nodeMenu = [
    {
      text: 'Open page',
      title: 'Open the page of this node',
      variant: 'outline-primary',
      visible: (node) => (ipOf(node) !== '' || fqdnOf(node) !== '') && hrefOf(node) !== '',
      onclick: (event, node) => window.location.assign(hrefOf(node)),
    },
    {
      text: 'Open IP graph',
      title: 'Graph of the names seen on this address',
      variant: 'outline-primary',
      visible: (node) => ipOf(node) !== '',
      onclick: (event, node) => window.location.assign(`/graph/ip/${encodeURIComponent(ipOf(node))}`),
    },
    {
      text: 'Enrich with VT',
      title: 'Look up with VirusTotal',
      variant: 'outline-primary',
      visible: (node) => canEnrich && (ipOf(node) !== '' || fqdnOf(node) !== ''),
      onclick: (event, node) => enrichNode(node),
    },
  ];

  const draw = (g) => {
    if (g.excluded_cdn > 0) {
      document.getElementById('graph-cdn-count').textContent = String(g.excluded_cdn);
      show('graph-cdn');
    }
    if (g.truncated) show('graph-truncated');

    graph = new window.Pivotick(box, { nodes: g.nodes.map(toNode), edges: g.edges.map(toEdge) }, {
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
        onNodeClick: (event, node) => expand(node),
      },
    });
  };

  fetch(box.dataset.source, { headers: { Accept: 'application/json' } })
    .then(getJSON)
    .then(draw)
    .catch((err) => fail(err.message));
})();
