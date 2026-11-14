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

  // withParam returns the page URL with name=value, without name if value
  // is ''.
  const withParam = (name, value) => {
    const u = new URL(window.location.href);
    if (value) u.searchParams.set(name, value);
    else u.searchParams.delete(name);
    return u.toString();
  };

  const withVT = (on) => withParam('vt', on ? '1' : '');

  // The VirusTotal box is remembered per graph page, 'on' or 'off'.
  const vtKey = `heimdall.graph.vt:${window.location.pathname}`;
  const rememberVT = (on) => {
    try {
      window.localStorage.setItem(vtKey, on ? 'on' : 'off');
    } catch (e) {
      // Storage unavailable: nothing is remembered.
    }
  };
  const rememberedVT = () => {
    try {
      return window.localStorage.getItem(vtKey);
    } catch (e) {
      return null;
    }
  };

  // vtControls wires the boxes of the bar; it reports true when it reloads
  // the page to restore VirusTotal.
  const vtControls = () => {
    const toggle = document.getElementById('graph-vt-toggle');
    if (toggle) {
      const vt = new URL(window.location.href).searchParams.get('vt');
      if (vt !== null) {
        rememberVT(vt === '1');
      } else if (rememberedVT() === 'on') {
        window.location.replace(withVT(true));
        return true;
      }
      toggle.addEventListener('change', () => {
        rememberVT(toggle.checked);
        window.location.assign(withVT(toggle.checked));
      });
    }

    // Subdomains are on by default: only subs=0 is kept in the URL.
    const subs = document.getElementById('graph-subs-toggle');
    if (subs) subs.addEventListener('change', () => window.location.assign(withParam('subs', subs.checked ? '' : '0')));

    const summary = document.getElementById('graph-vt-summary');
    if (summary && window.heimdallVTJob) {
      window.heimdallVTJob.watch(summary, document.getElementById('graph-vt-enrich'), withVT(true));
    }
    return false;
  };

  if (vtControls()) return;

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
      nsset: n.kind === 'nsset' ? n.id.slice('ns:'.length) : '',
    },
  });

  // An edge is unique by (from, kind, to).
  const edgeKey = (from, kind, to) => `${from}|${kind}|${to}`;

  const toEdge = (e) => ({
    id: edgeKey(e.from, e.kind, e.to),
    from: e.from,
    to: e.to,
    data: { kind: e.kind, first_seen: e.first_seen, last_seen: e.last_seen },
  });

  // newEdges converts edges, leaving out those whose key is in seen or
  // repeats one before; it adds the keys it keeps to seen.
  const newEdges = (edges, seen = new Set()) =>
    edges.map(toEdge).filter((e) => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });

  const dataOf = (node) => (node && typeof node.getData === 'function' && node.getData()) || {};
  const edgeData = (edge) => (typeof edge.getData === 'function' ? edge.getData() : edge.data) || {};
  const ipOf = (node) => dataOf(node).ip || '';
  const fqdnOf = (node) => dataOf(node).fqdn || '';
  const hrefOf = (node) => {
    const href = dataOf(node).href;
    return typeof href === 'string' && href.startsWith('/') && !href.startsWith('//') ? href : '';
  };

  const isAnalyst = box.dataset.analyst === '1';
  const canEnrich = box.dataset.vt === '1' && isAnalyst;
  const sourceParams = new URL(box.dataset.source, window.location.href).searchParams;
  const pageVT = sourceParams.get('vt') === '1';
  const pageSubs = sourceParams.get('subs') !== '0';
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

  // expandURL reads the graph of node; that of a domain has its SUB edges
  // unless the page has none, and merge keeps them.
  const expandURL = (node) => {
    const nsset = dataOf(node).nsset;
    if (nsset) return `/graph/ns/${encodeURIComponent(nsset)}/data`;
    let path = '';
    if (ipOf(node)) path = `/graph/ip/${encodeURIComponent(ipOf(node))}/data`;
    else if (fqdnOf(node)) path = `/graph/domain/${encodeURIComponent(fqdnOf(node))}/data`;
    if (!path) return '';
    const params = new URLSearchParams();
    if (pageVT || enriched.has(node.id)) params.set('vt', '1');
    if (!pageSubs && fqdnOf(node)) params.set('subs', '0');
    const query = params.toString();
    return query ? `${path}?${query}` : path;
  };

  // around places the i-th of count new nodes on a ring around node.
  const around = (n, node, i, count) => {
    if (typeof node.x !== 'number' || typeof node.y !== 'number') return n;
    const a = (2 * Math.PI * i) / count;
    return { ...n, x: node.x + 60 * Math.cos(a), y: node.y + 60 * Math.sin(a) };
  };

  // union joins graphs, each node and edge once.
  const union = (graphs) => {
    const nodes = new Map();
    const edges = new Map();
    graphs.forEach((g) => {
      g.nodes.forEach((n) => {
        if (!nodes.has(n.id)) nodes.set(n.id, n);
      });
      g.edges.forEach((e) => {
        const id = toEdge(e).id;
        if (!edges.has(id)) edges.set(id, e);
      });
    });
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  };

  // merge adds the nodes of g the graph lacks around node, at most
  // maxExpand, and the edges of g between nodes of the graph, but not one
  // whose (from, kind, to) the graph has under another id.
  const merge = (node, g) => {
    const fresh = g.nodes.filter((n) => !graph.getMutableNode(n.id));
    const added = fresh.slice(0, maxExpand);
    const ids = new Set(added.map((n) => n.id));
    const present = (id) => ids.has(id) || !!graph.getMutableNode(id);
    const seen = new Set(
      graph
        .getMutableEdges()
        .filter((e) => !e.isSynthetic)
        .map((e) => edgeKey(e.from.id, edgeData(e).kind, e.to.id)),
    );
    const edges = newEdges(
      g.edges.filter((e) => present(e.from) && present(e.to)),
      seen,
    );
    // An empty update still redraws.
    graph.updateData(added.map((n, i) => around(toNode(n), node, i, added.length)), edges);
    if (fresh.length > maxExpand) expandStatus(`+${fresh.length - maxExpand} not shown`);
    else if (added.length === 0) expandStatus('no neighbours');
    else expandStatus('');
  };

  // enrichGraph reads the graph of the last enrichment of fqdn, empty when
  // there is none (404) or the name cannot be enriched (400).
  const enrichGraph = (fqdn) =>
    fetch(`/domains/${encodeURIComponent(fqdn)}/enrich/data`, { headers: { Accept: 'application/json' } }).then((res) => {
      if (res.status === 404 || res.status === 400) return { nodes: [], edges: [] };
      return getJSON(res).then((d) => d.graph);
    });

  // expand merges the graph of node into the current one, with that of the
  // last enrichment of a domain node, once per node.
  const expand = (node) => {
    const url = expandURL(node);
    if (!graph || !url || expanded.has(node.id) || pending.has(node.id)) return;
    pending.add(node.id);
    const reads = [fetch(url, { headers: { Accept: 'application/json' } }).then(getJSON)];
    if (fqdnOf(node)) reads.push(enrichGraph(fqdnOf(node)));
    Promise.all(reads)
      .then((graphs) => {
        expanded.add(node.id);
        mark(node, true);
        merge(node, union(graphs));
      })
      .catch((err) => expandStatus(`Expand failed: ${err.message}`))
      .finally(() => pending.delete(node.id));
  };

  // enrichDomain enriches the name of node, following the job in the graph
  // bar, then merges the graph of the enrichment around the node.
  const enrichDomain = (node) => {
    const status = document.getElementById('graph-enrich');
    if (!status || !window.heimdallVTJob) return;
    const fqdn = fqdnOf(node);
    window.heimdallVTJob.enrich(status, `/domains/${encodeURIComponent(fqdn)}/enrich`, box.dataset.csrf, () => {
      enrichGraph(fqdn)
        .then((g) => {
          if (graph) merge(graph.getMutableNode(node.id) || node, g);
        })
        .catch((err) => expandStatus(`Enrichment graph unavailable: ${err.message}`));
    });
  };

  // linkNode opens the "Link to campaign" dialog for the name of node, which
  // is drawn watched once linked.
  const linkNode = (node) => {
    window.heimdallLink.open(fqdnOf(node), (res) => {
      const n = graph && graph.getMutableNode(node.id);
      if (!n) return;
      n.updateData({ type: 'domain-watched', campaign: res.campaign.name });
      graph.updateData([], []);
    });
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

  // realEdges returns the edges a synthetic edge stands for, through the
  // synthetic ones among them.
  const realEdges = (edge, out = []) => {
    if (edge.isSynthetic) (edge.representedEdges || []).forEach((e) => realEdges(e, out));
    else out.push(edge);
    return out;
  };

  // The kind drawn for parallel edges of several kinds, strongest first.
  const kindPriority = ['SUB', 'TRACKER', 'CNAME', 'REDIRECT', 'A', 'AAAA', 'MX', 'NS_SET', 'CERT', 'VT'];

  // shownId is the id of the node drawn for node: itself, or the group that
  // hides it.
  const shownId = (node) => (typeof node.canvasRepresentative === 'function' ? node.canvasRepresentative() : node).id;

  // edgeKind styles an edge by its kind. Pivotick draws one synthetic edge
  // for all the edges between two drawn nodes: when they all join those two
  // nodes, it takes the strongest of their kinds; when some go through a
  // grouped node, the kind they share, else MIXED.
  const edgeKind = (edge) => {
    if (!edge.isSynthetic) return edgeData(edge).kind;
    const edges = realEdges(edge);
    const kinds = new Set(edges.map((e) => edgeData(e).kind).filter(Boolean));
    const ends = new Set([shownId(edge.from), shownId(edge.to)]);
    const parallel = edges.every((e) => e.from.id !== e.to.id && ends.has(e.from.id) && ends.has(e.to.id));
    const strongest = parallel && kindPriority.find((k) => kinds.has(k));
    if (strongest) return strongest;
    return kinds.size === 1 ? [...kinds][0] : 'MIXED';
  };

  const labelOf = (node) => (node && (dataOf(node).label || node.id)) || '?';
  const day = (ts) => (typeof ts === 'string' ? ts.slice(0, 10) : '');

  // edgeProperties fills the tooltip and the properties panel of an edge:
  // Pivotick's default, or for a synthetic edge its real path, one line per
  // edge.
  const edgeProperties = (edge) => {
    if (!edge.isSynthetic) {
      const props = [{ name: 'id', value: edge.id }];
      Object.entries(edgeData(edge)).forEach(([name, value]) => {
        if (name && value) props.push({ name, value });
      });
      return props;
    }
    const path = document.createElement('div');
    path.className = 'graph-edge-path';
    realEdges(edge).forEach((e) => {
      const d = edgeData(e);
      let line = `${labelOf(e.from)} → ${labelOf(e.to)} (${d.kind || '?'})`;
      if (d.first_seen || d.last_seen) line += ` ${day(d.first_seen) || '?'} – ${day(d.last_seen) || '?'}`;
      const row = document.createElement('div');
      row.textContent = line;
      path.append(row);
    });
    return [{ name: 'path', value: path }];
  };

  // The members of a group node, listed in a side panel.
  const panel = document.getElementById('graph-group');
  const panelFilter = document.getElementById('graph-group-filter');
  let panelMembers = [];

  const memberType = (node) => {
    const t = dataOf(node).type;
    return t === 'domain-watched' ? 'domain' : t || '?';
  };

  const openPage = (node) => {
    const href = hrefOf(node);
    if (href) window.open(href, '_blank', 'noopener');
  };

  // showMember opens the groups that hide member, as Pivotick's own search
  // does, then selects and centres it; without that API, it opens its page.
  const showMember = (member) => {
    try {
      const node = graph.getMutableNode(member.id) || member;
      let shown = node.canvasRepresentative();
      while (shown.isGroup) {
        graph.simplify.open(shown);
        const next = node.canvasRepresentative();
        if (next === shown) break;
        shown = next;
      }
      graph.selectElement(node);
      graph.focusElement(node);
    } catch (e) {
      openPage(member);
    }
  };

  const memberItem = (m) => {
    const li = document.createElement('li');
    if (dataOf(m).type === 'domain-watched') {
      const dot = document.createElement('span');
      dot.className = 'graph-group-watched';
      dot.title = 'watched';
      li.append(dot);
    }
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'graph-group-member';
    button.title = 'Show in the graph';
    button.textContent = labelOf(m);
    button.addEventListener('click', () => showMember(m));
    const kind = document.createElement('span');
    kind.className = 'badge';
    kind.textContent = memberType(m);
    li.append(button, kind);
    const href = hrefOf(m);
    if (href) {
      const page = document.createElement('a');
      page.href = href;
      page.target = '_blank';
      page.rel = 'noopener';
      page.textContent = 'page';
      li.append(page);
    }
    return li;
  };

  const renderMembers = () => {
    const q = panelFilter.value.trim().toLowerCase();
    const shown = panelMembers.filter((m) => labelOf(m).toLowerCase().includes(q));
    document.getElementById('graph-group-list').replaceChildren(...shown.map(memberItem));
    document.getElementById('graph-group-count').textContent = `${shown.length} / ${panelMembers.length}`;
  };

  const groupLabel = (node) => {
    try {
      return graph.simplify.labelOf(node.info) || 'Group';
    } catch (e) {
      return 'Group';
    }
  };

  const openGroupPanel = (node) => {
    if (!panel || !node.info) return;
    panelMembers = [...(node.info.members || [])].sort(
      (a, b) => memberType(a).localeCompare(memberType(b)) || labelOf(a).localeCompare(labelOf(b)),
    );
    document.getElementById('graph-group-title').textContent = `${groupLabel(node)} (${panelMembers.length} members)`;
    panelFilter.value = '';
    renderMembers();
    panel.hidden = false;
    panelFilter.focus();
  };

  if (panel) {
    panelFilter.addEventListener('input', renderMembers);
    document.getElementById('graph-group-close').addEventListener('click', () => {
      panel.hidden = true;
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !panel.hidden) panel.hidden = true;
    });
  }

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
    {
      text: 'Enrich',
      title: 'Live DNS, RDAP, Certificate Transparency and subdomains of this name',
      variant: 'outline-primary',
      visible: (node) => isAnalyst && fqdnOf(node) !== '',
      onclick: (event, node) => enrichDomain(node),
    },
    {
      text: 'Link to campaign',
      title: 'Put this name in a campaign of the watchlist',
      variant: 'outline-primary',
      visible: (node) => isAnalyst && fqdnOf(node) !== '' && !!window.heimdallLink,
      onclick: (event, node) => linkNode(node),
    },
  ];

  const draw = (g) => {
    if (g.excluded_cdn > 0) {
      document.getElementById('graph-cdn-count').textContent = String(g.excluded_cdn);
      show('graph-cdn');
    }
    if (g.truncated) show('graph-truncated');

    graph = new window.Pivotick(box, { nodes: g.nodes.map(toNode), edges: newEdges(g.edges) }, {
      UI: {
        mode: 'light',
        editors: { nodeCreator: { enabled: false }, edgeCreator: { enabled: false }, nodeEditor: { enabled: false } },
        notes: { enabled: false },
        contextMenu: { menuNode: { menu: nodeMenu } },
        tooltip: { edgePropertiesMap: edgeProperties },
        propertiesPanel: { edgePropertiesMap: edgeProperties },
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
          tracker: { color: color('--graph-tracker') },
          vt: { color: color('--graph-vt-node') },
        },
        defaultNodeStyle: {
          text: (node) => node.getData().label,
          textVerticalShift: -1,
          textColor: color('--fg'),
          textTruncate: false,
        },
        edgeTypeAccessor: edgeKind,
        edgeStyleMap: {
          A: { strokeColor: color('--graph-ip') },
          AAAA: { strokeColor: color('--graph-ip') },
          CNAME: { strokeColor: color('--graph-domain') },
          NS_SET: { strokeColor: color('--graph-nsset') },
          MIXED: { dashed: true, animateDash: false, strokeColor: color('--graph-mixed'), strokeWidth: 1.5 },
          VT: { dashed: true, animateDash: false, strokeColor: color('--graph-vt') },
          MX: { strokeColor: color('--graph-mx') },
          CERT: { dashed: true, animateDash: false, strokeColor: color('--graph-cert') },
          SUB: { strokeColor: color('--graph-sub') },
          REDIRECT: { strokeColor: color('--graph-redirect') },
          TRACKER: { strokeColor: color('--graph-tracker') },
        },
      },
      callbacks: {
        onNodeClick: (event, node) => (node && node.isGroup ? openGroupPanel(node) : expand(node)),
      },
    });
  };

  fetch(box.dataset.source, { headers: { Accept: 'application/json' } })
    .then(getJSON)
    .then(draw)
    .catch((err) => fail(err.message));
})();
