// Draws /campaigns/{id}/analytics from the JSON at data-source.
(() => {
  'use strict';

  const root = document.getElementById('analytics');
  if (!root) return;

  const NS = 'http://www.w3.org/2000/svg';
  const ROW_H = 18;
  const VIRTUAL = 300;
  const PAD = { l: 34, r: 6, t: 6, b: 16 };
  const KPIS = [
    ['resolving', 'Resolving'],
    ['nxdomain', 'NXDOMAIN'],
    ['failing', 'Failing'],
    ['unmeasured', 'Unmeasured'],
    ['active_ips', 'Active IPs'],
    ['cdn_share', 'CDN share'],
    ['ns_sets', 'NS sets'],
    ['events_7d', 'Events 7 d'],
  ];
  const STATE_LABEL = { ok: 'resolving', nx: 'NXDOMAIN', fail: 'failing', none: 'no observation' };
  const STATE_RANK = { ok: 0, fail: 1, nx: 2, none: 3 };
  // Kinds with a colour of their own in analytics.css; the others use k-other.
  const KINDS = new Set(['new_rdata', 'removed_rdata', 'nxdomain', 'resurrection', 'ns_sinkhole', 'ns_parking', 'soa_serial_change', 'ttl_change']);
  const NEW_IPS = 15;

  const st = {
    data: null,
    days: Number(root.dataset.window) === 90 ? 90 : 30,
    range: null,
    hidden: new Set(),
    sort: 'state',
    hl: new Set(),
    rows: [],
  };

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

  const svg = (tag, attrs) => {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
    return n;
  };

  const getJSON = (res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const fmtTS = (s) => (s ? s.replace('T', ' ').replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)$/, '') : '—');
  const fmtDay = (s) => (s ? s.slice(0, 10) : '—');
  const kindClass = (kind) => (KINDS.has(kind) ? `k-${kind}` : 'k-other');
  const dayOf = (ts) => new Date(ts).toISOString().slice(0, 10);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const inRange = (i) => !st.range || (i >= st.range[0] && i <= st.range[1]);
  const safeHref = (h) => (typeof h === 'string' && h.startsWith('/') && !h.startsWith('//') ? h : null);

  // activate runs fn on click, Enter and Space.
  const activate = (node, fn) => {
    node.addEventListener('click', fn);
    node.addEventListener('keydown', (e) => {
      if (e.target !== node || (e.key !== 'Enter' && e.key !== ' ')) return;
      e.preventDefault();
      fn();
    });
  };

  const linkButton = (label, fn) => {
    const b = el('button', { type: 'button', class: 'an-link', text: label });
    b.addEventListener('click', (e) => {
      e.stopPropagation();
      fn();
    });
    return b;
  };

  const domainButton = (name) => {
    const fqdn = name.startsWith('zone:') ? name.slice(5) : name;
    return linkButton(name.startsWith('zone:') ? `zone ${fqdn}` : fqdn, () => openDomain(fqdn));
  };

  const ipButton = (ip) => linkButton(ip, () => openIP(ip));

  const table = (head, rows) => el('table', { class: 'an-table' },
    el('thead', {}, el('tr', {}, ...head.map((h) => el('th', { text: h })))),
    el('tbody', {}, ...rows.map((cells) => el('tr', {}, ...cells.map((c) => el('td', {}, c))))));

  const kindLabel = (kind) => el('span', { class: 'an-kind' }, el('span', { class: `an-swatch ${kindClass(kind)}` }), kind);

  // Header and KPIs.

  const renderHeader = () => {
    const h = st.data.header;
    $('an-counts').textContent = `${plural(h.domains, 'domain', 'domains')} · ${h.enabled} enabled`;
    $('an-measured').textContent = `last measured ${fmtTS(h.last_measured_at)}`;
    const vt = $('an-vt');
    vt.hidden = !h.vt;
    if (h.vt) vt.textContent = `VT ${h.vt.remaining} / ${h.vt.budget} lookups left today`;
    for (const b of root.querySelectorAll('[data-days]')) {
      b.setAttribute('aria-pressed', String(Number(b.dataset.days) === st.days));
    }
  };

  const sparkline = (series, label) => {
    const n = series.length;
    const max = Math.max(...series, 0) || 1;
    const s = svg('svg', {
      viewBox: `0 -0.08 ${Math.max(n - 1, 1)} 1.16`, preserveAspectRatio: 'none',
      class: 'an-spark', role: 'img', 'aria-label': label,
    });
    s.append(svg('polyline', { points: series.map((v, i) => `${i},${(1 - v / max).toFixed(3)}`).join(' ') }));
    return s;
  };

  const fmtKPI = (key, v) => (key === 'cdn_share' ? `${Math.round(v * 100)}%` : String(v));

  const renderKPIs = () => {
    const box = $('an-kpis');
    box.replaceChildren();
    for (const [key, label] of KPIS) {
      const k = st.data.kpis[key];
      box.append(el('div', { class: `an-kpi an-kpi-${key}` },
        el('span', { class: 'an-kpi-label', text: label }),
        el('span', { class: 'an-kpi-value', text: fmtKPI(key, k.value) }),
        sparkline(k.series, `${label}, one point per day over ${st.days} days`)));
    }
  };

  // Timeline with a brush.

  const renderLegend = () => {
    const box = $('an-legend');
    box.replaceChildren();
    for (const kind of st.data.timeline.kinds) {
      const b = el('button', { type: 'button', 'aria-pressed': String(!st.hidden.has(kind)) },
        el('span', { class: `an-swatch ${kindClass(kind)}` }), kind);
      b.addEventListener('click', () => {
        if (st.hidden.has(kind)) st.hidden.delete(kind);
        else st.hidden.add(kind);
        renderLegend();
        renderTimeline();
      });
      box.append(b);
    }
  };

  const tick = (x, y, label, anchor) => {
    const t = svg('text', { x, y, class: 'an-tick', 'text-anchor': anchor });
    t.textContent = label;
    return t;
  };

  const renderTimeline = () => {
    const box = $('an-timeline');
    const days = st.data.timeline.days;
    const kinds = st.data.timeline.kinds.filter((k) => !st.hidden.has(k));
    const w = Math.max(box.clientWidth, 320);
    const h = 150;
    const ih = h - PAD.t - PAD.b;
    const bw = (w - PAD.l - PAD.r) / days.length;
    const totals = days.map((d) => kinds.reduce((n, k) => n + (d.counts[k] || 0), 0));
    const max = Math.max(...totals, 1);
    const s = svg('svg', {
      width: w, height: h, role: 'img',
      'aria-label': `Events per day and kind over ${days.length} days, at most ${max} a day`,
    });
    s.append(
      svg('line', { x1: PAD.l, x2: w - PAD.r, y1: PAD.t + ih + 0.5, y2: PAD.t + ih + 0.5, class: 'an-axis' }),
      tick(PAD.l - 4, PAD.t + 8, String(max), 'end'),
      tick(PAD.l - 4, PAD.t + ih, '0', 'end'),
    );
    const every = Math.ceil(days.length / 8);
    days.forEach((d, i) => {
      let y = PAD.t + ih;
      for (const k of kinds) {
        const n = d.counts[k] || 0;
        if (!n) continue;
        const bh = (n / max) * ih;
        y -= bh;
        const r = svg('rect', {
          x: PAD.l + i * bw + 0.5, y, width: Math.max(bw - 1, 1), height: bh,
          class: `${kindClass(k)}${inRange(i) ? '' : ' dim'}`,
        });
        const title = svg('title');
        title.textContent = `${d.day} · ${k}: ${n}`;
        r.append(title);
        s.append(r);
      }
      if (i % every === 0) s.append(tick(PAD.l + i * bw, h - 3, d.day.slice(5), 'start'));
    });
    const brush = svg('rect', { class: 'an-brush', y: PAD.t, height: ih, x: 0, width: 0 });
    const show = (lo, hi) => {
      brush.setAttribute('x', String(PAD.l + lo * bw));
      brush.setAttribute('width', String((hi - lo + 1) * bw));
    };
    if (st.range) show(st.range[0], st.range[1]);
    s.append(brush);

    const col = (e) => {
      const x = e.clientX - s.getBoundingClientRect().left - PAD.l;
      return Math.min(days.length - 1, Math.max(0, Math.floor(x / bw)));
    };
    s.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const a = col(e);
      let r = [a, a];
      show(a, a);
      const move = (ev) => {
        const b = col(ev);
        r = [Math.min(a, b), Math.max(a, b)];
        show(r[0], r[1]);
      };
      const up = () => {
        window.removeEventListener('mousemove', move);
        window.removeEventListener('mouseup', up);
        setRange(r);
      };
      window.addEventListener('mousemove', move);
      window.addEventListener('mouseup', up);
    });
    box.replaceChildren(s);
  };

  const setRange = (r) => {
    st.range = r;
    const days = st.data.liveness.days;
    $('an-reset').hidden = !r;
    $('an-range-label').textContent = r ? `${days[r[0]]} → ${days[r[1]]}` : '';
    renderTimeline();
    renderMatrix();
    renderNewIPs();
    renderEvents();
  };

  // Liveness matrix, virtualised past VIRTUAL rows.

  const cmpSeen = (a, b) => {
    if (a === b) return 0;
    if (!a) return 1;
    if (!b) return -1;
    return a < b ? -1 : 1;
  };

  const sortRows = () => {
    const last = (r) => r.cells[r.cells.length - 1];
    const okDays = (r) => r.cells.reduce((n, c) => n + (c === 'ok' ? 1 : 0), 0);
    const rows = st.data.liveness.rows.slice();
    if (st.sort === 'ok') {
      rows.sort((a, b) => okDays(b) - okDays(a) || a.fqdn.localeCompare(b.fqdn));
    } else {
      rows.sort((a, b) => STATE_RANK[last(a)] - STATE_RANK[last(b)] || cmpSeen(a.first_seen, b.first_seen) || a.fqdn.localeCompare(b.fqdn));
    }
    st.rows = rows;
  };

  const matrixRow = (r, index) => {
    const n = r.cells.length;
    const ok = r.cells.filter((c) => c === 'ok').length;
    const div = el('div', {
      class: `an-row${st.hl.has(r.fqdn) ? ' hl' : ''}${r.enabled ? '' : ' off'}`,
      tabindex: '0', role: 'button', 'data-row': index,
      'aria-label': `${r.fqdn}, ${STATE_LABEL[r.cells[n - 1]]} today, open details`,
    }, el('span', { class: 'an-fqdn', text: r.fqdn, title: r.fqdn }));
    const s = svg('svg', {
      viewBox: `0 0 ${n} 1`, preserveAspectRatio: 'none', class: 'an-cells',
      role: 'img', 'aria-label': `${r.fqdn}: resolving ${ok} of ${n} days`,
    });
    r.cells.forEach((c, i) => {
      s.append(svg('rect', { x: i, y: 0, width: 0.88, height: 1, 'data-i': i, class: `s-${c}${inRange(i) ? '' : ' dim'}` }));
    });
    div.append(s);
    return div;
  };

  let matrixRows = null;

  const renderMatrixRows = () => {
    if (!matrixRows) return;
    const box = $('an-matrix');
    const rows = st.rows;
    let from = 0;
    let to = rows.length;
    if (rows.length > VIRTUAL) {
      from = Math.max(0, Math.floor(box.scrollTop / ROW_H) - 10);
      to = Math.min(rows.length, from + Math.ceil(box.clientHeight / ROW_H) + 20);
    }
    matrixRows.style.transform = `translateY(${from * ROW_H}px)`;
    const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.row : undefined;
    matrixRows.replaceChildren(...rows.slice(from, to).map((r, k) => matrixRow(r, from + k)));
    if (focused !== undefined) {
      const again = matrixRows.querySelector(`[data-row="${focused}"]`);
      if (again) again.focus({ preventScroll: true });
    }
  };

  const renderMatrix = () => {
    const box = $('an-matrix');
    const days = st.data.liveness.days;
    if (!st.rows.length) {
      box.replaceChildren(el('p', { class: 'an-empty', text: 'No domains in this campaign.' }));
      matrixRows = null;
      return;
    }
    const mid = days[Math.floor(days.length / 2)];
    const head = el('div', { class: 'an-matrix-head' },
      el('span', { class: 'an-fqdn', text: plural(st.rows.length, 'domain', 'domains') }),
      el('div', { class: 'an-days' }, el('span', { text: days[0] }), el('span', { text: mid }), el('span', { text: days[days.length - 1] })));
    matrixRows = el('div', { class: 'an-matrix-rows' });
    const body = el('div', { class: 'an-matrix-body' }, matrixRows);
    body.style.height = `${st.rows.length * ROW_H}px`;
    box.replaceChildren(head, body);
    renderMatrixRows();
  };

  const rowAt = (target) => {
    const row = target.closest('.an-row');
    return row ? st.rows[Number(row.dataset.row)] : null;
  };

  const tip = $('an-tip');
  const showTip = (e, text) => {
    tip.textContent = text;
    tip.hidden = false;
    tip.style.left = `${e.clientX + 12}px`;
    tip.style.top = `${e.clientY + 14}px`;
  };

  const matrixEvents = () => {
    const box = $('an-matrix');
    box.addEventListener('click', (e) => {
      const r = rowAt(e.target);
      if (r) openDomain(r.fqdn);
    });
    box.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const r = rowAt(e.target);
      if (!r) return;
      e.preventDefault();
      openDomain(r.fqdn);
    });
    box.addEventListener('mousemove', (e) => {
      const cell = e.target.closest('rect[data-i]');
      const r = cell && rowAt(cell);
      if (!r) {
        tip.hidden = true;
        return;
      }
      const i = Number(cell.dataset.i);
      showTip(e, `${r.fqdn} · ${st.data.liveness.days[i]} · ${STATE_LABEL[r.cells[i]]}`);
    });
    box.addEventListener('mouseleave', () => {
      tip.hidden = true;
    });
    let pending = false;
    box.addEventListener('scroll', () => {
      if (pending || st.rows.length <= VIRTUAL) return;
      pending = true;
      window.requestAnimationFrame(() => {
        pending = false;
        renderMatrixRows();
      });
    });
  };

  const highlight = (node, fqdns) => {
    const on = () => {
      st.hl = new Set(fqdns);
      renderMatrixRows();
    };
    const off = () => {
      st.hl = new Set();
      renderMatrixRows();
    };
    node.addEventListener('mouseenter', on);
    node.addEventListener('mouseleave', off);
    node.addEventListener('focusin', on);
    node.addEventListener('focusout', off);
  };

  // Clusters.

  const renderClusters = () => {
    const c = st.data.clusters;
    const ips = $('an-ips');
    ips.replaceChildren();
    if (!c.ips.length) ips.append(el('li', { class: 'an-empty', text: 'No address shared by two domains.' }));
    for (const x of c.ips) {
      const li = el('li', { tabindex: '0', role: 'button', 'aria-label': `${x.ip}, shared by ${x.domains.length} domains, open details` },
        el('span', { class: 'an-mono', text: x.ip }),
        el('span', { class: 'an-count', text: plural(x.domains.length, 'domain', 'domains') }),
        el('span', { class: 'an-dim an-mono', text: `${fmtDay(x.first_seen)} → ${fmtDay(x.last_seen)}` }));
      highlight(li, x.domains);
      activate(li, () => openIP(x.ip));
      ips.append(li);
    }
    $('an-cdn').textContent = c.excluded_cdn ? `${plural(c.excluded_cdn, 'CDN address', 'CDN addresses')} left out` : '';

    const ns = $('an-ns');
    ns.replaceChildren();
    if (!c.ns_sets.length) ns.append(el('li', { class: 'an-empty', text: 'No NS set shared by two zones.' }));
    for (const x of c.ns_sets) {
      const li = el('li', {},
        el('span', { class: 'an-mono', text: x.ns.join(', ') }),
        el('span', { class: 'an-count', text: plural(x.zones.length, 'zone', 'zones') }),
        el('span', {}, ...x.zones.map((z) => domainButton(z))));
      highlight(li, x.domains);
      ns.append(li);
    }
  };

  const renderNewIPs = () => {
    const box = $('an-newips');
    const days = st.data.clusters.new_ips_per_day;
    const picked = days.map((d, i) => ({ ...d, i })).filter((d) => inRange(d.i) && d.ips.length);
    const total = picked.reduce((n, d) => n + d.ips.length, 0);
    const items = picked.reverse().flatMap((d) => d.ips.map((ip) => ({ ip, day: d.day })));
    const item = (x) => el('li', {}, ipButton(x.ip), el('span', { class: 'an-dim an-mono', text: x.day }));
    const ul = el('ul', { class: 'an-list' }, ...items.slice(0, NEW_IPS).map(item));
    box.replaceChildren(
      sparkline(days.map((d) => d.ips.length), `New addresses per day over ${days.length} days`),
      el('p', { class: 'an-dim', text: `${plural(total, 'address', 'addresses')} first seen${st.range ? ' in range' : ''}` }),
      ul,
    );
    if (items.length > NEW_IPS) {
      const more = el('button', { type: 'button', class: 'an-more', text: `${items.length - NEW_IPS} more` });
      more.addEventListener('click', () => {
        ul.append(...items.slice(NEW_IPS).map(item));
        more.remove();
      });
      box.append(more);
    }
  };

  // Events.

  const renderEvents = () => {
    const kind = $('an-ev-kind').value;
    const q = $('an-ev-q').value.trim().toLowerCase();
    const days = st.data.liveness.days;
    const lo = st.range ? days[st.range[0]] : '';
    const hi = st.range ? days[st.range[1]] : '';
    const rows = st.data.events.filter((e) => {
      const day = dayOf(e.ts);
      if (st.range && (day < lo || day > hi)) return false;
      if (kind && e.kind !== kind) return false;
      return !q || `${e.domain} ${JSON.stringify(e.detail)}`.toLowerCase().includes(q);
    });
    const body = $('an-ev-body');
    body.replaceChildren();
    if (!rows.length) body.append(el('tr', {}, el('td', { colspan: 5, class: 'an-empty', text: 'No events.' })));
    for (const e of rows) {
      const detail = e.detail === null ? '' : JSON.stringify(e.detail);
      body.append(el('tr', {},
        el('td', { class: 'nowrap', text: fmtTS(e.ts) }),
        el('td', {}, kindLabel(e.kind)),
        el('td', {}, domainButton(e.domain)),
        el('td', { text: e.qtype }),
        el('td', { class: 'an-detail', text: detail, title: detail })));
    }
    $('an-ev-count').textContent = `${rows.length} of ${st.data.events.length}`;
  };

  const fillKinds = () => {
    const sel = $('an-ev-kind');
    if (sel.options.length > 1) return;
    for (const k of st.data.timeline.kinds) sel.append(el('option', { value: k, text: k }));
  };

  // VirusTotal leads.

  const addForm = (host) => el('form', { method: 'post', action: `/campaigns/${root.dataset.campaign}/domains`, class: 'an-add' },
    el('input', { type: 'hidden', name: 'csrf_token', value: root.dataset.csrf }),
    el('input', { type: 'hidden', name: 'fqdns', value: host }),
    el('input', { type: 'hidden', name: 'interval', value: '300' }),
    el('button', { type: 'submit', text: 'Add to campaign' }));

  const renderLeads = () => {
    const leads = st.data.vt_leads;
    $('an-leads-panel').hidden = !leads;
    if (!leads) return;
    const analyst = root.dataset.analyst === '1';
    const body = $('an-leads-body');
    body.replaceChildren();
    if (!leads.length) body.append(el('tr', {}, el('td', { colspan: analyst ? 5 : 4, class: 'an-empty', text: 'No name outside the watchlist in the cache.' })));
    for (const l of leads) {
      body.append(el('tr', {},
        el('td', {}, domainButton(l.host_name)),
        el('td', { text: String(l.ips.length) }),
        el('td', {}, ...l.ips.map((ip) => ipButton(ip)).flatMap((b, i) => (i ? [' ', b] : [b]))),
        el('td', { class: 'nowrap', text: fmtTS(l.last_seen) }),
        analyst ? el('td', {}, addForm(l.host_name)) : null));
    }
  };

  // Side panel.

  const drawer = $('an-drawer');
  let lastFocus = null;
  let drawerSeq = 0;

  const section = (title, ...kids) => el('section', {}, el('h3', { text: title }), ...kids);
  const dl = (pairs) => el('dl', {}, ...pairs.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', {}, v)]));
  const links = (...pairs) => el('p', { class: 'an-links' }, ...pairs.filter(([h]) => safeHref(h)).map(([h, label]) => el('a', { href: safeHref(h), text: label })));

  const openDrawer = (title, url, draw) => {
    if (drawer.hidden) lastFocus = document.activeElement;
    $('an-drawer-title').textContent = title;
    const body = $('an-drawer-body');
    body.replaceChildren(el('p', { class: 'an-dim', text: 'Loading…' }));
    drawer.hidden = false;
    drawer.focus();
    const seq = ++drawerSeq;
    fetch(url, { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((d) => {
        if (seq === drawerSeq) body.replaceChildren(...draw(d));
      })
      .catch((err) => {
        if (seq === drawerSeq) body.replaceChildren(el('p', { class: 'an-error', text: `Unavailable: ${err.message}` }));
      });
  };

  const closeDrawer = () => {
    if (drawer.hidden) return;
    drawer.hidden = true;
    drawerSeq++;
    if (lastFocus && lastFocus.isConnected) lastFocus.focus();
  };

  const vtStatus = (v) => (v.status ? `last looked up ${fmtTS(v.looked_up_at)} (${v.status})` : 'not looked up yet');

  const drawDomain = (d) => {
    const out = [links([d.href, 'Domain page'], [d.graph, 'Graph'])];
    out.push(section('Seen', dl([
      ['first seen', fmtTS(d.first_seen)],
      ['last seen', fmtTS(d.last_seen)],
      ['watchlist', d.domain ? `${d.domain.campaign || 'no campaign'}${d.domain.enabled ? '' : ', disabled'}` : 'not watched'],
    ])));
    const cur = d.current.filter((c) => c.qtype === 'A' || c.qtype === 'AAAA' || c.qtype === 'NS');
    out.push(section('Current state', cur.length
      ? table(['QType', 'Resolver', 'Rcode', 'Data'], cur.map((c) => [
        c.qtype, c.resolver, c.rcode,
        el('span', {}, ...c.rdata.flatMap((v, i) => {
          const node = c.qtype === 'NS' ? domainButton(v) : ipButton(v);
          const cdn = c.cdn && c.cdn[v] ? el('span', { class: 'an-dim', text: ` CDN ${c.cdn[v]}` }) : null;
          return [i ? ' ' : null, node, cdn].filter((x) => x !== null);
        })),
      ]))
      : el('p', { class: 'an-empty', text: 'No A, AAAA or NS answer in the last 7 days.' })));
    out.push(section('Recent events', d.events.length
      ? table(['Time (UTC)', 'Kind', 'QType'], d.events.map((e) => [fmtTS(e.ts), kindLabel(e.kind), e.qtype]))
      : el('p', { class: 'an-empty', text: 'No events in the last 90 days.' })));
    if (d.vt) {
      out.push(section('VirusTotal', el('p', { class: 'an-dim', text: vtStatus(d.vt) }), d.vt.resolutions.length
        ? table(['Address', 'First seen', 'Last seen'], d.vt.resolutions.map((r) => [ipButton(r.ip), fmtTS(r.first_seen), fmtTS(r.last_seen)]))
        : el('p', { class: 'an-empty', text: 'No resolution in the cache.' })));
    }
    return out;
  };

  const drawIP = (d) => {
    const out = [links([d.href, 'Passive DNS'], [`/graph/campaign/${root.dataset.campaign}`, 'Campaign graph'])];
    if (d.cdn) out.push(el('p', { class: 'an-notice', text: `CDN address (${d.cdn}): sharing it is not an infrastructure link` }));
    out.push(section('Names in Heimdall', d.names.length
      ? table(['Name', 'Types', 'Last seen', 'Watchlist'], d.names.map((n) => [
        domainButton(n.rrname), n.rrtypes.join(', '), fmtTS(n.last_seen), n.watched ? n.campaign || 'watched' : '—',
      ]))
      : el('p', { class: 'an-empty', text: 'No passive DNS record holds this address.' })));
    if (d.truncated) out.push(el('p', { class: 'an-dim', text: 'Limited to the most recent records.' }));
    if (d.vt) {
      out.push(section('VirusTotal', el('p', { class: 'an-dim', text: vtStatus(d.vt) }), d.vt.names.length
        ? table(['Name', 'Last seen', 'Watchlist'], d.vt.names.map((n) => [domainButton(n.host_name), fmtTS(n.last_seen), n.watched ? n.campaign || 'watched' : '—']))
        : el('p', { class: 'an-empty', text: 'No name in the cache.' })));
    }
    return out;
  };

  const openDomain = (fqdn) => openDrawer(fqdn, `/entity/domain/${encodeURIComponent(fqdn)}`, drawDomain);
  const openIP = (ip) => openDrawer(ip, `/entity/ip/${encodeURIComponent(ip)}`, drawIP);

  // Loading and controls.

  const render = () => {
    renderHeader();
    renderKPIs();
    renderLegend();
    fillKinds();
    sortRows();
    renderClusters();
    renderLeads();
    setRange(null);
  };

  const load = () => {
    const u = new URL(root.dataset.source, window.location.origin);
    u.searchParams.set('days', String(st.days));
    const err = $('an-error');
    err.hidden = true;
    root.setAttribute('aria-busy', 'true');
    fetch(u, { headers: { Accept: 'application/json' } })
      .then(getJSON)
      .then((d) => {
        st.data = d;
        render();
      })
      .catch((e) => {
        err.textContent = `Analytics unavailable: ${e.message}`;
        err.hidden = false;
      })
      .finally(() => root.removeAttribute('aria-busy'));
  };

  for (const b of root.querySelectorAll('[data-days]')) {
    b.addEventListener('click', () => {
      st.days = Number(b.dataset.days);
      const u = new URL(window.location.href);
      u.searchParams.set('days', String(st.days));
      window.history.replaceState(null, '', u);
      load();
    });
  }
  $('an-reset').addEventListener('click', () => setRange(null));
  $('an-sort').addEventListener('change', (e) => {
    st.sort = e.target.value;
    sortRows();
    renderMatrix();
  });
  $('an-ev-kind').addEventListener('change', () => st.data && renderEvents());
  $('an-ev-q').addEventListener('input', () => st.data && renderEvents());
  $('an-drawer-close').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer();
  });
  let resize = 0;
  window.addEventListener('resize', () => {
    window.clearTimeout(resize);
    resize = window.setTimeout(() => st.data && renderTimeline(), 150);
  });
  matrixEvents();
  load();
})();
