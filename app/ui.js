// Shared widget helpers.  ->  Bailee.ui   (load after crypto.js)
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};

  // Tiny shared helpers for the Bailee widgets. No framework, ~80 lines.
  // Every widget renders a self-contained <section class="widget"> body.

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const $ = (el, sel) => el.querySelector(sel);
  const $$ = (el, sel) => Array.from(el.querySelectorAll(sel));

  const short = (s, n = 10) =>
    s && s.length > n * 2 + 3 ? s.slice(0, n) + '\u2026' + s.slice(-n) : s || '';

  const money = (n) =>
    '$' + Math.round(n).toLocaleString('en-US');

  const nowISO = () => new Date().toISOString();

  function fmtDate(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return String(iso);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  }

  // Mount a widget into [data-widget="name"] (or #w-name). No-ops if absent.
  // render(element, mode) replaces the element's contents. mode comes from data-mode.
  function mount(name, render) {
    const go = () => {
      const byId = ['widget-' + name, 'w-' + name]
        .map((id) => document.getElementById(id)).filter(Boolean);
      const els = new Set([...document.querySelectorAll(`[data-widget="${name}"]`), ...byId]);
      for (const el of els) {
        if (el.dataset.mounted) continue;   // module already rendered this one
        el.dataset.mounted = name;
        el.classList.add('widget');
        el.innerHTML = '';
        try { render(el, el.dataset.mode || 'full'); }
        catch (err) {
          el.innerHTML = `<p class="bad">Widget "${esc(name)}" failed: ${esc(err.message)}</p>`;
          console.error(err);
        }
      }
    };
    if (typeof document === 'undefined') return;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
    else go();
  }

  // Click-to-copy on any element carrying data-copy.
  function wireCopy(root) {
    root.addEventListener('click', async (e) => {
      const t = e.target.closest('[data-copy]');
      if (!t) return;
      const text = t.dataset.copy === 'self' ? t.textContent.trim() : t.dataset.copy;
      try {
        await navigator.clipboard.writeText(text);
        const old = t.getAttribute('data-label') || '';
        t.classList.add('copied');
        setTimeout(() => t.classList.remove('copied'), 900);
        void old;
      } catch { /* clipboard blocked on file:// in some browsers; selection still works */ }
    });
  }

  function row(label, value, cls = '') {
    return `<div class="kv"><span class="k">${esc(label)}</span>
      <span class="v ${cls}">${value}</span></div>`;
  }

  function monoBlock(text, label) {
    return `<div class="monoblock" title="click to copy" data-copy="${esc(text)}">
      ${label ? `<span class="mb-label">${esc(label)}</span>` : ''}
      <code>${esc(text)}</code></div>`;
  }

  /* ------------------------------------------------------------- registry */
  // The trust root. A certificate or an attestation is only a pass if the key that
  // signed it is listed here, and this list never travels inside the payload.
  //
  // registry.json on disk is the source of truth. This embedded copy exists so the
  // page still works when it is double-clicked (fetch() of a relative path fails
  // under file://). Keep the two in step; loadRegistry() reports which one it used.
  const REGISTRY_EMBEDDED = {
    "schema": "bailment.ai/registry/v1",
    "_comment": "DEMO REGISTRY WITH DEMO KEYS. The two key pairs below were generated for this working demonstration and their private halves are embedded in the page source, so anyone can mint a certificate that this registry accepts. It shows the shape of the real thing: in production this file is the published, append-only registry, the private halves live under the 3-of-5 root, and nothing here is a trust anchor.",
    "updated": "2026-09-21",
    "approvedSigners": [
      {
        "id": "demo-attestation-service",
        "role": "attestation-service",
        "fingerprint": "7B85 3961 7630 61AB",
        "spki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt6ZGDXumjls6Ld5EnjgJ3n4R57W_XIo7-VQJCv8b-hv7CYxJqtgMvehXQz_HugnJlDOxW0gvo8lp2Y521y5-XQ",
        "firm": "Bailment attestation service (demo key)",
        "name": "Bailment attestation service",
        "signs": [
          "certificate"
        ],
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": "2027-12-31T23:59:59.000Z"
      },
      {
        "id": "demo-attorney-mohr",
        "role": "attorney",
        "fingerprint": "D408 F057 F718 76C2",
        "spki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2taL90NN8ctbfzJhGxVeisUPb7lyIT6VePWOA7sLAxULixRitelCWqvsGN06dO_1BUdEcEriOyG4AnvNy2N32w",
        "firm": "Bailment Law (demo key)",
        "name": "Kevin G. Mohr, Esq.",
        "barNumber": "Bar No. 123456",
        "jurisdiction": "Washington",
        "signs": [
          "attestation"
        ],
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validUntil": "2027-12-31T23:59:59.000Z"
      }
    ],
    "approvedPipelines": [
      {
        "registryEntry": "bailee-pipeline/2026.9.3",
        "approvedOn": "2026-09-03T00:00:00.000Z",
        "withdrawnOn": null
      },
      {
        "registryEntry": "bailee-pipeline/2026.8.1",
        "approvedOn": "2026-08-01T00:00:00.000Z",
        "withdrawnOn": "2026-09-03T00:00:00.000Z"
      }
    ]
  };

  let registryPromise = null;

  // Returns { registry, source: 'registry.json' | 'embedded copy', error }.
  // Never throws and never returns nothing: a verifier that cannot read the registry
  // must still fail closed rather than fall over.
  function loadRegistry(url = 'registry.json') {
    if (registryPromise) return registryPromise;
    registryPromise = (async () => {
      try {
        if (typeof fetch !== 'function') throw new Error('no fetch in this runtime');
        const res = await fetch(url, { cache: 'no-store' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const registry = await res.json();
        if (!registry || registry.schema !== REGISTRY_EMBEDDED.schema) throw new Error('unexpected registry schema');
        if (!Array.isArray(registry.approvedSigners) || !Array.isArray(registry.approvedPipelines)) {
          throw new Error('registry is missing approvedSigners or approvedPipelines');
        }
        return { registry, source: url, error: null };
      } catch (err) {
        return { registry: REGISTRY_EMBEDDED, source: 'embedded copy', error: err.message };
      }
    })();
    return registryPromise;
  }


  const normFP = (s) => String(s ?? '').replace(/\s+/g, '').toUpperCase();

  // Look a signing key up by SPKI first (the bytes that actually verified the
  // signature), fingerprint second. Returns the entry, or null.
  function registrySigner(registry, { spki, fingerprint, at, signs } = {}) {
    const list = (registry && registry.approvedSigners) || [];
    const when = at ? new Date(at) : new Date();
    for (const e of list) {
      const hit = (spki && e.spki === spki) || (fingerprint && normFP(e.fingerprint) === normFP(fingerprint));
      if (!hit) continue;
      if (signs && Array.isArray(e.signs) && !e.signs.includes(signs)) continue;
      const from = e.validFrom ? new Date(e.validFrom) : null;
      const until = e.validUntil ? new Date(e.validUntil) : null;
      const live = (!from || isNaN(from) || when >= from) && (!until || isNaN(until) || when <= until);
      return { ...e, live, window: { from: e.validFrom || null, until: e.validUntil || null } };
    }
    return null;
  }

  // Approved pipeline versions. A version that was withdrawn before the certificate
  // was issued is not approved for it.
  function registryPipeline(registry, entry, at) {
    const list = (registry && registry.approvedPipelines) || [];
    const when = at ? new Date(at) : new Date();
    const e = list.find((p) => p.registryEntry === entry);
    if (!e) return null;
    const approvedOn = e.approvedOn ? new Date(e.approvedOn) : null;
    const withdrawnOn = e.withdrawnOn ? new Date(e.withdrawnOn) : null;
    const live = (!approvedOn || isNaN(approvedOn) || isNaN(when) || when >= approvedOn)
      && (!withdrawnOn || isNaN(withdrawnOn) || isNaN(when) || when < withdrawnOn);
    return { ...e, live };
  }

  /* --------------------------------------------------------- demo inputs */
  // Nothing in a demo arrives pre-typed. Every field that used to carry invented text
  // is a dropdown: a neutral prompt or a sensible default, a couple of plausible
  // choices, and "Write my own" at the end. Choosing "Write my own" opens an empty box
  // and focuses it; clicking the box does the same thing, so nobody has to hunt for the
  // option. The value always comes from the field, never from text left sitting in it.
  const WM_OWN = '__wm_own__';
  const WM_OWN_LABEL = 'Write my own';

  const wmOpts = (options) =>
    (options || []).map((o) => (typeof o === 'string' ? { value: o, label: o } : o));

  // spec: { id, label, options, value, hint, placeholder, multiline, rows, cls, wrap }
  // An option with value '' is a neutral prompt: the field starts empty on purpose.
  // A `value` the list does not carry opens in the free-text box instead.
  // A "?" that explains itself: a real button so a keyboard reaches it, with the words in a
  // sibling the CSS reveals on :hover and on :focus-visible. Shared by every widget.
  let helpSeq = 0;
  function help(text, id) {
    if (!text) return '';
    const tid = id || ('wm-help-' + (++helpSeq));
    return `<span class="wm-help"><button type="button" class="wm-q" aria-describedby="${tid}"`
      + ` aria-label="What this means">?</button>`
      + `<span class="wm-tip" role="tooltip" id="${tid}">${esc(text)}</span></span>`;
  }

  function wmField(spec) {
    // One plain box per answer, carrying the sensible default. The old pattern was a
    // dropdown plus a hidden free-text twin; two controls for one answer is two chances
    // to sign something the reader was not looking at.
    const s = spec || {};
    const id = String(s.id);
    const opts = wmOpts(s.options);
    const value = s.value == null ? (opts[0] ? opts[0].value : '') : String(s.value);
    const attrs = `class="wm-input wm-box${s.cls ? ' ' + esc(s.cls) : ''}" id="${esc(id)}" `
      + `placeholder="${esc(s.placeholder || 'Type your own\u2026')}" aria-label="${esc(s.label || id)}"`;
    const box = s.multiline
      ? `<textarea ${attrs} rows="${Number(s.rows) || 3}">${esc(value)}</textarea>`
      : `<input type="text" ${attrs} value="${esc(value)}">`;
    return `<div class="field wm-field" data-wm="${esc(id)}">`
      + (s.label ? `<span class="wm-labelrow"><label for="${esc(id)}">${esc(s.label)}</label>`
          + help(s.help) + '</span>' : '')
      + box
      + '</div>';
  }

  const wmBox = (f) => f && f.querySelector('.wm-input');
  const wmSel = (f) => f && f.querySelector('.wm-select');
  const wmBtn = (f) => f && f.querySelector('[data-wm-own]');
  const wmFind = (root, id) => {
    const scope = root || (typeof document !== 'undefined' ? document : null);
    return scope ? scope.querySelector(`[data-wm="${id}"]`) : null;
  };

  // What the field is worth right now: the chosen option, or whatever was typed.
  function wmValue(root, id) {
    const f = wmFind(root, id);
    if (!f) {
      const scope = root || (typeof document !== 'undefined' ? document : null);
      const el = scope && scope.querySelector('#' + id);
      return el ? String(el.value == null ? '' : el.value) : '';
    }
    const sel = wmSel(f), box = wmBox(f);
    if (sel && sel.value !== WM_OWN) return String(sel.value == null ? '' : sel.value);
    return box ? String(box.value == null ? '' : box.value) : '';
  }

  function wmOpen(f, clear) {
    const sel = wmSel(f), box = wmBox(f), btn = wmBtn(f);
    if (sel) sel.value = WM_OWN;
    if (btn) btn.style.display = 'none';
    if (!box) return;
    box.style.display = '';
    if (clear) box.value = '';
    try { box.focus(); } catch { /* not focusable off-screen */ }
  }

  function wmClose(f) {
    const box = wmBox(f), btn = wmBtn(f);
    if (box) { box.value = ''; box.style.display = 'none'; }
    if (btn) btn.style.display = '';
  }

  // Set a field to a value from anywhere. A value the list carries selects that option;
  // anything else (including '') lands in the free-text box, which is where a value the
  // list does not carry belongs.
  function wmSet(root, id, value) {
    const v = String(value == null ? '' : value);
    const f = wmFind(root, id);
    if (!f) { const el = root && root.querySelector('#' + id); if (el) el.value = v; return; }
    const sel = wmSel(f), box = wmBox(f), btn = wmBtn(f);
    const listed = sel && Array.prototype.some.call(sel.options,
      (o) => o.value === v && o.value !== WM_OWN);
    if (listed) { sel.value = v; wmClose(f); return; }
    if (sel) sel.value = WM_OWN;
    if (btn) btn.style.display = 'none';
    if (box) { box.value = v; box.style.display = ''; }
  }

  // Put a field back to its first option with an empty box. Used after a send.
  function wmReset(root, id) {
    const f = wmFind(root, id);
    if (!f) { const s = root && root.querySelector('#' + id); if (s) s.value = ''; return; }
    const sel = wmSel(f);
    if (sel && sel.options.length) sel.selectedIndex = 0;
    wmClose(f);
  }

  // One delegated listener per container, so a widget that repaints itself does not
  // stack handlers. Both routes into free text live here.
  function wireFields(root) {
    if (!root || root.__wmWired) return;
    root.__wmWired = true;
    root.addEventListener('change', (e) => {
      const sel = e.target && e.target.closest ? e.target.closest('.wm-select') : null;
      if (!sel) return;
      const f = sel.closest('.wm-field');
      if (sel.value === WM_OWN) wmOpen(f, true); else wmClose(f);
    });
    root.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('[data-wm-own]') : null;
      if (!btn) return;
      e.preventDefault();
      wmOpen(btn.closest('.wm-field'), true);
    });
    // Clicking or tabbing into the box is itself the choice: keep what is typed.
    root.addEventListener('focusin', (e) => {
      const box = e.target && e.target.closest ? e.target.closest('.wm-input') : null;
      if (box) wmOpen(box.closest('.wm-field'), false);
    });
    root.addEventListener('input', (e) => {
      const box = e.target && e.target.closest ? e.target.closest('.wm-input') : null;
      if (box) { const s = wmSel(box.closest('.wm-field')); if (s) s.value = WM_OWN; }
    });
  }

  // A widget says "I finished a step" and a page that cares (all-together.html) listens.
  // Pages that do not listen lose nothing.
  const emit = (name, detail) => {
    if (typeof document !== 'undefined' && typeof CustomEvent !== 'undefined') {
      document.dispatchEvent(new CustomEvent(name, { detail: detail }));
    }
  };

  root.Bailee.ui = { esc, $, $$, short, money, nowISO, fmtDate, mount, wireCopy, row, monoBlock,
    REGISTRY_EMBEDDED, loadRegistry, registrySigner, registryPipeline, normFP,
    WM_OWN, WM_OWN_LABEL, wmField, wmValue, wmSet, wmReset, wireFields, help, emit };
})(typeof globalThis !== 'undefined' ? globalThis : this);
