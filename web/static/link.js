// The "Link to campaign" dialog of the domain and graph pages: puts a name
// in the current campaign, another one or a new one.
(() => {
  'use strict';

  const dialog = document.getElementById('link-campaign');
  if (!dialog) return;

  const byId = (id) => document.getElementById(id);
  const form = byId('link-form');
  const other = byId('link-other');
  const newName = byId('link-new-name');
  const newDescription = byId('link-new-description');
  const result = byId('link-result');
  const error = byId('link-error');
  const submit = byId('link-submit');
  const actions = { added: 'Added to', moved: 'Moved to', unchanged: 'Already in' };

  let fqdn = '';
  let onSuccess = null;

  const say = (el, msg) => {
    el.textContent = msg;
    el.hidden = msg === '';
  };

  const choice = (value) => form.querySelector(`input[name="link-choice"][value="${value}"]`);

  // open shows the dialog for name; done, if any, gets the answer of a
  // successful link.
  const open = (name, done) => {
    fqdn = name;
    onSuccess = done || null;
    byId('link-fqdn').textContent = name;
    say(result, '');
    say(error, '');
    submit.disabled = false;
    (choice('current') || (other.options.length > 0 ? choice('other') : choice('new'))).checked = true;
    dialog.showModal();
  };

  const body = () => {
    const picked = form.querySelector('input[name="link-choice"]:checked');
    if (!picked) return null;
    if (picked.value === 'current') return { campaign: Number(picked.dataset.campaign) };
    if (picked.value === 'other') return other.value ? { campaign: Number(other.value) } : null;
    return { new_campaign: { name: newName.value.trim(), description: newDescription.value.trim() } };
  };

  // addCampaign offers a campaign created here in the select.
  const addCampaign = (c) => {
    const o = document.createElement('option');
    o.value = String(c.id);
    o.textContent = c.name;
    other.append(o);
    choice('other').disabled = false;
    newName.value = '';
    newDescription.value = '';
  };

  other.addEventListener('change', () => {
    choice('other').checked = true;
  });
  newName.addEventListener('input', () => {
    choice('new').checked = true;
  });
  byId('link-cancel').addEventListener('click', () => dialog.close());

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const req = body();
    if (!req) {
      say(error, 'Choose a campaign.');
      return;
    }
    say(result, '');
    say(error, '');
    submit.disabled = true;
    fetch(`/domains/${encodeURIComponent(fqdn)}/link`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': dialog.dataset.csrf },
      body: JSON.stringify(req),
    })
      .then((res) =>
        res
          .json()
          .catch(() => ({}))
          .then((j) => {
            if (!res.ok) throw new Error(j.error || `HTTP ${res.status}`);
            return j;
          }),
      )
      .then((j) => {
        if (j.created_campaign) addCampaign(j.campaign);
        say(result, `${actions[j.action] || j.action} ${j.campaign.name}`);
        if (onSuccess) onSuccess(j);
      })
      .catch((err) => say(error, `Link failed: ${err.message}`))
      .finally(() => {
        submit.disabled = false;
      });
  });

  window.heimdallLink = { open };

  // The domain page reloads once the name is linked.
  const button = byId('link-open');
  if (button) button.addEventListener('click', () => open(button.dataset.fqdn, () => window.location.reload()));
})();
