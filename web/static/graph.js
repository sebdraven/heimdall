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

  // The enrichment summary survives the reload in sessionStorage.
  const summaryKey = 'heimdall.vt.summary';
  const pollEvery = 2000;

  const getJSON = (res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const summaryText = (j) => {
    let msg = `VirusTotal: looked up ${j.looked_up}, cached ${j.cached}, skipped for budget ${j.skipped_budget}` +
      `, CDN ${j.skipped_cdn}, reserved ${j.skipped_reserved}`;
    if (j.stopped_reason) msg += `, stopped: ${j.stopped_reason}`;
    return msg;
  };

  const withVT = (on) => {
    const u = new URL(window.location.href);
    if (on) u.searchParams.set('vt', '1');
    else u.searchParams.delete('vt');
    return u.toString();
  };

  const vtControls = () => {
    const saved = sessionStorage.getItem(summaryKey);
    if (saved) {
      sessionStorage.removeItem(summaryKey);
      say('graph-vt-summary', saved);
    }

    const toggle = document.getElementById('graph-vt-toggle');
    if (toggle) toggle.addEventListener('change', () => window.location.assign(withVT(toggle.checked)));

    const summary = document.getElementById('graph-vt-summary');
    const endpoint = summary && summary.dataset.endpoint;
    if (!endpoint) return;
    const button = document.getElementById('graph-vt-enrich');

    const failed = (msg) => {
      if (button) button.disabled = false;
      say('graph-vt-summary', `VirusTotal enrichment failed: ${msg}`);
    };

    const poll = () => fetch(endpoint, { headers: { Accept: 'application/json' } }).then(getJSON);

    // follow shows the state of the enrichment and polls it while it runs.
    const follow = (job) => {
      if (job.state === 'running') {
        if (button) button.disabled = true;
        say('graph-vt-summary', 'VirusTotal enrichment running…');
        window.setTimeout(() => poll().then(follow).catch((err) => failed(err.message)), pollEvery);
      } else if (job.state === 'done') {
        sessionStorage.setItem(summaryKey, summaryText(job));
        window.location.assign(withVT(true));
      } else if (job.state === 'failed') {
        failed(job.error || 'unknown error');
      }
    };

    // A finished job is not shown again: it would reload the page in a loop.
    poll()
      .then((job) => {
        if (job.state === 'running') follow(job);
      })
      .catch(() => {});

    if (!button) return;
    button.addEventListener('click', () => {
      button.disabled = true;
      fetch(endpoint, {
        method: 'POST',
        headers: { Accept: 'application/json', 'X-CSRF-Token': button.dataset.csrf },
      })
        .then(getJSON)
        .then(follow)
        .catch((err) => failed(err.message));
    });
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
          vt: { color: color('--graph-vt-node') },
        },
        defaultNodeStyle: {
          text: (node) => node.getData().label,
          textVerticalShift: -1,
          textColor: color('--fg'),
          // TODO: textTruncate: false, for full labels. Not added: the
          // Pivotick v3.0.0 type definitions were not available to confirm it.
        },
        // TODO: style VT edges (kind 'VT') dashed in color('--graph-vt'), with
        // first_seen / last_seen as tooltip or label. The Pivotick v3.0.0
        // type definitions were not available to confirm the option names
        // (edge style map or accessor, dash, colour, edge label or tooltip).
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
