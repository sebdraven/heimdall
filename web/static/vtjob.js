// Follows a VirusTotal enrichment: POST starts it, GET polls it every 2 s
// while it runs. Used by graph.js and the domain and rdata pages.
(() => {
  'use strict';

  // The summary survives the reload in sessionStorage.
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

  const say = (status, msg) => {
    status.textContent = msg;
    status.hidden = false;
  };

  // follower reports in status the job polled at endpoint, disabling the
  // button, if any, while it runs. A finished job reloads reloadURL, or the
  // page.
  const follower = (status, endpoint, button, reloadURL) => {
    const failed = (msg) => {
      if (button) button.disabled = false;
      say(status, `VirusTotal enrichment failed: ${msg}`);
    };

    const poll = () => fetch(endpoint, { headers: { Accept: 'application/json' } }).then(getJSON);

    const follow = (job) => {
      if (job.state === 'running') {
        if (button) button.disabled = true;
        say(status, 'VirusTotal enrichment running…');
        window.setTimeout(() => poll().then(follow).catch((err) => failed(err.message)), pollEvery);
      } else if (job.state === 'done') {
        sessionStorage.setItem(summaryKey, summaryText(job));
        if (reloadURL) window.location.assign(reloadURL);
        else window.location.reload();
      } else if (job.state === 'failed') {
        failed(job.error || 'unknown error');
      }
    };

    const start = (postURL, csrf) => {
      if (button) button.disabled = true;
      fetch(postURL, {
        method: 'POST',
        headers: { Accept: 'application/json', 'X-CSRF-Token': csrf },
      })
        .then(getJSON)
        .then(follow)
        .catch((err) => failed(err.message));
    };

    return { poll, follow, start };
  };

  // watch wires the status element, whose data-endpoint is the job, the
  // button and the depth select, if any.
  const watch = (status, button, reloadURL, depth) => {
    const saved = sessionStorage.getItem(summaryKey);
    if (saved) {
      sessionStorage.removeItem(summaryKey);
      say(status, saved);
    }

    const endpoint = status.dataset.endpoint;
    if (!endpoint) return;
    const job = follower(status, endpoint, button, reloadURL);

    // A finished job is not shown again: it would reload the page in a loop.
    job
      .poll()
      .then((j) => {
        if (j.state === 'running') job.follow(j);
      })
      .catch(() => {});

    if (!button) return;
    button.addEventListener('click', () => {
      let postURL = endpoint;
      if (depth) {
        const u = new URL(endpoint, window.location.href);
        u.searchParams.set('depth', depth.value);
        postURL = u.pathname + u.search;
      }
      job.start(postURL, button.dataset.csrf);
    });
  };

  // enrich starts the job at endpoint and reports it in status.
  const enrich = (status, endpoint, csrf, reloadURL) => follower(status, endpoint, null, reloadURL).start(endpoint, csrf);

  window.heimdallVTJob = { watch, enrich };

  // The domain and rdata pages.
  const status = document.getElementById('vt-job');
  if (status) watch(status, document.getElementById('vt-enrich'), null, document.getElementById('vt-depth'));
})();
