// Follows a VirusTotal enrichment: POST starts it, GET polls it every 2 s
// while it runs. Used by graph.js and the domain page.
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

  // watch wires the status element, whose data-endpoint is the job, and the
  // button, if any. A finished job reloads reloadURL, or the page.
  const watch = (status, button, reloadURL) => {
    const say = (msg) => {
      status.textContent = msg;
      status.hidden = false;
    };

    const saved = sessionStorage.getItem(summaryKey);
    if (saved) {
      sessionStorage.removeItem(summaryKey);
      say(saved);
    }

    const endpoint = status.dataset.endpoint;
    if (!endpoint) return;

    const failed = (msg) => {
      if (button) button.disabled = false;
      say(`VirusTotal enrichment failed: ${msg}`);
    };

    const poll = () => fetch(endpoint, { headers: { Accept: 'application/json' } }).then(getJSON);

    const follow = (job) => {
      if (job.state === 'running') {
        if (button) button.disabled = true;
        say('VirusTotal enrichment running…');
        window.setTimeout(() => poll().then(follow).catch((err) => failed(err.message)), pollEvery);
      } else if (job.state === 'done') {
        sessionStorage.setItem(summaryKey, summaryText(job));
        if (reloadURL) window.location.assign(reloadURL);
        else window.location.reload();
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

  window.heimdallVTJob = { watch };

  // The domain page.
  const status = document.getElementById('vt-job');
  if (status) watch(status, document.getElementById('vt-enrich'));
})();
