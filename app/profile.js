// The attorney profile. -> Bailee.profile   (load after ui.js)
//
// One identity, read from profile.json, kept in the browser. It fills the attorney block
// on a certificate, keeps the history of what this browser notarised and certified, and
// composes a disclosure email a judge can actually read. Nothing here is a server: the
// history is this device's, and the profile is a demonstration with a fictitious bar
// number and a key that is published on purpose.
(function (root) {
  'use strict';
  const UI = (root.Bailee && root.Bailee.ui) || {};
  const help = UI.help || (() => '');
  const esc = UI.esc || ((s) => String(s == null ? '' : s));
  const KEY_HISTORY = 'bailee.profile.history.v1';
  const KEY_EDITS = 'bailee.profile.edits.v1';

  let DATA = null;
  let privateShown = false;      // once per page load, on purpose

  function store() { try { return root.localStorage; } catch (e) { return null; } }
  function readJSON(k, fallback) {
    const s = store();
    if (!s) return fallback;
    try { return JSON.parse(s.getItem(k)) || fallback; } catch (e) { return fallback; }
  }
  function writeJSON(k, v) { const s = store(); if (s) { try { s.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode */ } } }

  const DEFAULTS = {
    attorney: { name: 'Kevin G. Mohr, Esq.', barNumber: 'Bar No. 123456', jurisdiction: 'Nevada',
      court: 'Second Judicial District Court, Washoe County, Nevada',
      role: 'Partner, Nevada Law', status: 'Demo profile \u2014 credentials are fictitious' },
    firm: { name: 'Bailment Law', address: ['1023 Taos Ranch Court', 'Reno, NV 89511', 'United States'],
      email: 'admin@bailment.tech', phone: '845-587-4420',
      licence: 'blf_lk_demo_bailment_law_0001', registryEntry: 'bailee-pipeline/2026.9.3' },
    keys: { id: 'demo-attorney-mohr', fingerprint: '', publicKey: '', note: '' },
    disclosure: { name: 'Judge Washoe', email: 'Judge@washoecourts.example', subjectPrefix: 'Disclosure of AI use' },
  };

  async function load() {
    if (DATA) return DATA;
    let base = DEFAULTS;
    try {
      const r = await fetch('profile.json', { cache: 'no-store' });
      if (r.ok) base = Object.assign({}, DEFAULTS, await r.json());
    } catch (e) { /* opened from a file: the defaults above are the same profile */ }
    const edits = readJSON(KEY_EDITS, {});
    DATA = {
      attorney: Object.assign({}, base.attorney, edits.attorney || {}),
      firm: Object.assign({}, base.firm, edits.firm || {}),
      keys: Object.assign({}, base.keys),
      disclosure: Object.assign({}, base.disclosure, edits.disclosure || {}),
    };
    return DATA;
  }

  function initials(name) {
    const parts = String(name || '?').replace(/,.*$/, '').split(/\s+/).filter(Boolean);
    return ((parts[0] || '?')[0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
  }

  /* ------------------------------------------------------------- history */
  // Every notarisation and certification this browser did, newest first. It is evidence
  // for the person who made it, not a server-side record: clearing the browser clears it.
  function history() { return readJSON(KEY_HISTORY, []); }
  function record(entry) {
    if (!entry || !entry.kind) return null;
    const row = Object.assign({ at: new Date().toISOString() }, entry);
    const all = history();
    all.unshift(row);
    writeJSON(KEY_HISTORY, all.slice(0, 200));
    paintOpen();
    return row;
  }

  /* ------------------------------------------------------------ the email */
  // A real message in the reader's own mail client. Nothing is sent from here.
  function disclosureEmail(rows, d) {
    const when = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    const a = DATA.attorney, f = DATA.firm;
    const lines = [];
    lines.push('Dear ' + (d.name || 'Judge') + ',');
    lines.push('');
    lines.push('In accordance with the standing order on the use of artificial intelligence in');
    lines.push('filings, I disclose the following records of AI use. Each entry can be checked');
    lines.push('independently: the certificate verifies against a published signing key, and the');
    lines.push('commitment proves the document existed in the form certified, without disclosing');
    lines.push('the document itself.');
    lines.push('');
    rows.forEach(function (r, i) {
      lines.push(String(i + 1) + '. ' + (r.kind === 'certification' ? 'Certificate of AI use'
        : 'Document Record notarisation' + (r.by === 'client' ? ' (made by the client)' : '')));
      lines.push('   Date            ' + new Date(r.at).toLocaleString('en-US'));
      if (r.title) lines.push('   Matter or filing ' + r.title);
      if (r.digest) lines.push('   Document digest  ' + r.digest);
      if (r.commitment) lines.push('   Commitment       ' + r.commitment);
      if (r.model) lines.push('   Model            ' + r.model);
      if (r.identifiersRemoved != null) lines.push('   Identifiers removed before the record was made: ' + r.identifiersRemoved);
      if (r.verifyUrl) lines.push('   Verify at        ' + r.verifyUrl);
      lines.push('');
    });
    lines.push('I remain responsible for the contents of every filing above. The certificate');
    lines.push('records how the work was done; it is not a substitute for my own review, and I');
    lines.push('adopted each filing before it was submitted.');
    lines.push('');
    lines.push('Respectfully submitted,');
    lines.push('');
    lines.push(a.name);
    lines.push(a.role);
    lines.push(a.barNumber + ' \u00b7 ' + a.jurisdiction);
    lines.push(f.name);
    (f.address || []).forEach((l) => lines.push(l));
    lines.push(f.email + ' \u00b7 ' + f.phone);
    lines.push('');
    lines.push('Dated ' + when + '.');
    return lines.join('\n');
  }

  /* -------------------------------------------------------------- the UI */
  function tabsHTML(active) {
    return ['attorney', 'firm', 'keys', 'notarizations', 'certifications', 'disclose']
      .map((t) => '<button class="pf-tab' + (t === active ? ' on' : '') + '" data-pf-tab="' + t + '">'
        + esc(t.charAt(0).toUpperCase() + t.slice(1)) + '</button>').join('');
  }
  const field = (id, label, value) => '<label class="pf-field"><span>' + esc(label) + '</span>'
    + '<input id="' + esc(id) + '" value="' + esc(value || '') + '"></label>';
  const line = (k, v, why) => '<div class="pf-line"><span>' + esc(k) + (why ? help(why) : '')
    + '</span><b>' + esc(v || '\u2014') + '</b></div>';

  function copyBox(id, label, value, warn) {
    return '<div class="pf-key"><span class="pf-keylabel">' + esc(label) + '</span>'
      + '<textarea readonly id="' + esc(id) + '" rows="3">' + esc(value) + '</textarea>'
      + '<button class="btn ghost" data-pf-copy="' + esc(id) + '">Copy</button>'
      + (warn ? '<p class="pf-warn">' + warn + '</p>' : '') + '</div>';
  }

  // Old entries carry no `by` or `matter`: they were the lawyer's, under their title.
  const byOf = (r) => (r.by === 'client' ? 'client' : 'lawyer');
  const caseOf = (r) => r.matter || r.title || 'Untitled';
  let caseFilter = '';
  function historyHTML(kind) {
    const all = history().filter((r) => r.kind === kind);
    const cases = all.map(caseOf).filter((c, i, a) => a.indexOf(c) === i);
    if (caseFilter && cases.indexOf(caseFilter) < 0) caseFilter = '';
    const rows = caseFilter ? all.filter((r) => caseOf(r) === caseFilter) : all;
    const filter = cases.length > 1 || caseFilter
      ? '<label class="pf-filter">Case <select id="pf-case"><option value="">All cases</option>'
        + cases.map((c) => '<option value="' + esc(c) + '"' + (c === caseFilter ? ' selected' : '') + '>'
          + esc(c) + '</option>').join('') + '</select></label>'
      : '';
    if (!rows.length) {
      return '<p class="muted">Nothing yet. ' + (kind === 'certification'
        ? 'Sign a certificate and it lands here.'
        : 'Notarize a message or a document and it lands here.') + '</p>';
    }
    return filter + '<ul class="pf-hist">' + rows.map(function (r) {
      return '<li><label><input type="checkbox" class="pf-pick" data-at="' + esc(r.at) + '">'
        + (kind === 'notarization' ? '<span class="pf-by ' + byOf(r) + '">' + byOf(r) + '</span>' : '')
        + '<span class="pf-when">' + esc(new Date(r.at).toLocaleString('en-US')) + '</span>'
        + '<span class="pf-what">' + esc(r.title || r.kind) + '</span>'
        + '<code>' + esc(String(r.commitment || r.digest || '').slice(0, 16)) + '\u2026</code></label></li>';
    }).join('') + '</ul>';
  }

  function paneHTML(tab) {
    const a = DATA.attorney, f = DATA.firm, k = DATA.keys, d = DATA.disclosure;
    if (tab === 'attorney') {
      return '<p class="muted">These four fields are what a certificate carries in Step 4 '
        + '&mdash; attorney adoption. Edits stay in this browser.</p>'
        + field('pf-name', 'Name on filings', a.name)
        + field('pf-bar', 'Bar number', a.barNumber)
        + field('pf-juris', 'Jurisdiction', a.jurisdiction)
        + field('pf-court', 'Specific court', a.court)
        + field('pf-role', 'Role', a.role)
        + '<div class="actions"><button class="btn" data-pf-act="save">Save to this browser</button>'
        + '<button class="btn ghost" data-pf-act="fill">Fill Step 4 on this page</button></div>'
        + '<p class="pf-warn">' + esc(a.status) + '. A real deployment reads this from the firm\u2019s '
        + 'roster and the bar\u2019s own register, and a certificate is refused if the two disagree.</p>';
    }
    if (tab === 'firm') {
      return line('Firm', f.name) + line('Address', (f.address || []).join(', '))
        + line('Email', f.email) + line('Phone', f.phone)
        + line('Licence key', f.licence, 'The firm\u2019s password for the appliance. It opens cases and pays for each certification ($0.10) and notarization ($0.01). It can never send a message; only a named lawyer can.')
        + line('Appliance API', f.appliance || 'http://127.0.0.1:8402', 'The appliance is the firm\u2019s own server. It runs the AI and stores the case. Without one, the demo uses a built-in stand-in.')
        + line('Registry entry', f.registryEntry)
        + line('Signing key id', k.id) + line('Key fingerprint', k.fingerprint)
        + '<p class="muted">The licence is what pays for certifications and notarizations. The registry entry is '
        + 'the pipeline a verifier checks this firm\u2019s certificates against.</p>';
    }
    if (tab === 'keys') {
      return copyBox('pf-pub', 'Public key (SPKI, base64url)', k.publicKey,
          'Published in <code>registry.json</code>. A verifier reads it from there, not from this page. '
          + 'Sharing it is the point.')
        + '<div class="pf-key"><span class="pf-keylabel">Private key</span>'
        + '<div id="pf-privslot"><button class="btn" data-pf-act="genpriv">Generate a private key</button>'
        + '<p class="muted">Shown once. Refresh the page if you want to run the demo again.</p></div></div>';
    }
    if (tab === 'notarizations') return historyHTML('notarization');
    if (tab === 'certifications') return historyHTML('certification');
    return '<p class="muted">Pick entries under Notarizations or Certifications, then send them. '
      + 'This composes the message in your own mail client. Nothing is sent from this page.</p>'
      + field('pf-to-name', 'Recipient', d.name)
      + field('pf-to-email', 'Email', d.email)
      + field('pf-subject', 'Subject', d.subjectPrefix + ' \u2014 ' + DATA.attorney.name)
      + '<div class="actions"><button class="btn" data-pf-act="compose">Compose the disclosure</button></div>'
      + '<pre class="pf-preview" id="pf-preview"></pre>';
  }

  let current = 'attorney';
  function paintOpen() {
    const dlg = root.document && root.document.getElementById('bailee-profile');
    if (!dlg || !dlg.open) return;
    paint(dlg);
  }
  function paint(dlg) {
    dlg.querySelector('.pf-tabs').innerHTML = tabsHTML(current);
    dlg.querySelector('.pf-pane').innerHTML = paneHTML(current);
    if (current === 'keys' && privateShown) showPrivate(dlg, true);
  }

  function showPrivate(dlg, already) {
    const slot = dlg.querySelector('#pf-privslot');
    if (!slot) return;
    const hex = (n) => Array.from((root.crypto && root.crypto.getRandomValues)
      ? root.crypto.getRandomValues(new Uint8Array(n)) : new Uint8Array(n))
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    if (!privateShown) { privateShown = hex(32); }
    const value = typeof privateShown === 'string' ? privateShown : hex(32);
    slot.innerHTML = '<textarea readonly id="pf-priv" rows="3">' + esc(value) + '</textarea>'
      + '<button class="btn ghost" data-pf-copy="pf-priv">Copy</button>'
      + '<p class="pf-warn"><b>Store this somewhere only you can reach.</b> A private key is not a '
      + 'password: nobody can reset it, and anyone holding it can sign in your name. Never paste it '
      + 'into an email, a chat, a support ticket or a web page. Bailment cannot recover it and will '
      + 'never ask you for it.</p>'
      + '<p class="muted">Demo only. This one was generated in your browser, is shown once per page '
      + 'load, and is registered nowhere. A real key is created inside the appliance and never '
      + 'appears in a browser at all.' + (already ? '' : '') + '</p>';
  }

  function ensureDialog() {
    const doc = root.document;
    let dlg = doc.getElementById('bailee-profile');
    if (dlg) return dlg;
    dlg = doc.createElement('dialog');
    dlg.id = 'bailee-profile';
    dlg.className = 'pf-dialog';
    dlg.innerHTML = '<div class="pf-top"><div class="pf-who"><span class="pf-avatar">'
      + esc(initials(DATA.attorney.name)) + '</span><div><b>' + esc(DATA.attorney.name) + '</b>'
      + '<small>' + esc(DATA.attorney.role) + ' \u00b7 ' + esc(DATA.firm.name) + '</small></div></div>'
      + '<button class="btn ghost" data-pf-act="close">Close</button></div>'
      + '<div class="pf-tabs"></div><div class="pf-pane"></div>';
    doc.body.appendChild(dlg);
    dlg.addEventListener('click', onClick);
    dlg.addEventListener('change', function (e) {
      if (e.target && e.target.id === 'pf-case') { caseFilter = e.target.value; paint(dlg); }
    });
    return dlg;
  }

  async function open(tab) {
    await load();
    current = tab || current;
    const dlg = ensureDialog();
    paint(dlg);
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', 'open');
  }

  function fillStep4() {
    const doc = root.document;
    const put = (sel, v) => { const b = doc.querySelector(sel); if (b && v) b.value = v; };
    put('#ct-atty', DATA.attorney.name);
    put('#ct-bar', DATA.attorney.barNumber);
    put('#ct-court-specific', DATA.attorney.court);
    const juris = doc.querySelector('#ct-juris-pick') || doc.querySelector('#ct-juris');
    if (juris && DATA.attorney.jurisdiction) juris.value = DATA.attorney.jurisdiction;
    return true;
  }

  function onClick(e) {
    const t = e.target && e.target.closest ? e.target : null;
    if (!t) return;
    const dlg = root.document.getElementById('bailee-profile');
    const tab = t.closest('[data-pf-tab]');
    if (tab) { current = tab.dataset.pfTab; paint(dlg); return; }
    const copy = t.closest('[data-pf-copy]');
    if (copy) {
      const box = dlg.querySelector('#' + copy.dataset.pfCopy);
      if (box) { box.select(); try { root.document.execCommand('copy'); } catch (err) { /* clipboard blocked */ } }
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy'; }, 1200);
      return;
    }
    const act = t.closest('[data-pf-act]');
    if (!act) return;
    const name = act.dataset.pfAct;
    if (name === 'close') { dlg.close ? dlg.close() : dlg.removeAttribute('open'); return; }
    if (name === 'genpriv') { showPrivate(dlg); return; }
    if (name === 'save') {
      const v = (id) => (dlg.querySelector('#' + id) || {}).value || '';
      DATA.attorney = Object.assign(DATA.attorney, {
        name: v('pf-name'), barNumber: v('pf-bar'), jurisdiction: v('pf-juris'),
        court: v('pf-court'), role: v('pf-role'),
      });
      writeJSON(KEY_EDITS, { attorney: DATA.attorney, disclosure: DATA.disclosure });
      act.textContent = 'Saved';
      setTimeout(() => { act.textContent = 'Save to this browser'; }, 1200);
      return;
    }
    if (name === 'fill') {
      fillStep4();
      act.textContent = 'Filled Step 4';
      setTimeout(() => { act.textContent = 'Fill Step 4 on this page'; }, 1400);
      return;
    }
    if (name === 'compose') {
      const picked = Array.from(root.document.querySelectorAll('.pf-pick:checked')).map((b) => b.dataset.at);
      const rows = history().filter((r) => picked.indexOf(r.at) >= 0);
      const use = rows.length ? rows : history().slice(0, 3);
      const v = (id) => (dlg.querySelector('#' + id) || {}).value || '';
      DATA.disclosure = { name: v('pf-to-name'), email: v('pf-to-email'), subjectPrefix: DATA.disclosure.subjectPrefix };
      const body = disclosureEmail(use, DATA.disclosure);
      const pre = dlg.querySelector('#pf-preview');
      if (pre) pre.textContent = use.length ? body : 'Nothing to disclose yet. Notarize or certify something first.';
      if (use.length) {
        root.location.href = 'mailto:' + encodeURIComponent(DATA.disclosure.email)
          + '?subject=' + encodeURIComponent(v('pf-subject'))
          + '&body=' + encodeURIComponent(body);
      }
    }
  }

  async function mountButton() {
    if (typeof root.document === 'undefined') return;
    await load();
    const navs = root.document.querySelectorAll('.nav-inner');
    navs.forEach(function (nav) {
      if (nav.querySelector('.pf-button')) return;
      const b = root.document.createElement('button');
      b.className = 'pf-button';
      b.type = 'button';
      b.title = DATA.attorney.name + ' \u2014 profile';
      b.setAttribute('aria-label', 'Attorney profile');
      b.innerHTML = '<span class="pf-avatar">' + esc(initials(DATA.attorney.name)) + '</span>';
      b.addEventListener('click', () => open());
      nav.appendChild(b);
    });
  }

  if (typeof root.document !== 'undefined') {
    if (root.document.readyState === 'loading') {
      root.document.addEventListener('DOMContentLoaded', mountButton);
    } else { mountButton(); }
  }

  root.Bailee = root.Bailee || {};
  root.Bailee.profile = { load, open, record, history, disclosureEmail, fillStep4, DEFAULTS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
