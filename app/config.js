// config.js — the public pages, as set from the admin.
//
// A classic script, like every other file in this folder: no module, no build step, no
// dependency. It asks the API what the site should say and applies the answer to any
// element carrying a data-config attribute:
//
//   <h1 data-config="headline">                    the authored copy stays in the HTML
//   <p  data-config="subline">
//   <a  data-config="contactEmail" href="mailto:">
//   <span data-config="demoBanner">
//   <b  data-config="pricing.certification">
//   <div data-config="announcement">               optional; one is made if none exists
//
// It also applies the developer section of the same config — the part an administrator
// sets on the admin console's Developer tab:
//
//   theme     fontScale, spacing, lineHeight and six palette colours, written into one
//             <style data-bailee-theme> block as custom properties on :root. The names
//             are the ones tokens.css already uses, so nothing in style.css changes.
//   labels    the nav and footer link text, matched on the href the link already has.
//             A link carrying child elements (the brand, with its logo) is never touched.
//   features  each [data-widget] mount, on or off. The banners have their own `show`.
//
// The rule that matters: if the API is unreachable, this file does NOTHING. The page
// keeps exactly the words it was written with, which is why the site still works when
// you double-click site/index.html from a file. Every failure here is silent on purpose.
// The same goes for a config that arrives malformed: a colour that is not a colour and a
// font scale outside the clamp are ignored, one value at a time, never applied and never
// thrown. The server refuses both; this is the second door, for when it is not the server
// answering.
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};

  // Where to look, in order. The last one is the copy shipped beside the pages.
  function sources() {
    var out = [];
    try {
      if (root.BAILEE_API) out.push(String(root.BAILEE_API).replace(/\/+$/, '') + '/v1/site-config');
      var p = (root.location && root.location.protocol) || '';
      if (p === 'http:' || p === 'https:') { out.push('/v1/site-config'); out.push('site-config.json'); }
    } catch (e) { /* silent */ }
    return out;
  }

  function money(n) {
    var v = Number(n);
    if (!isFinite(v)) return null;
    var s = (Math.round(v * 100) % 100 === 0) ? String(Math.round(v)) : v.toFixed(2);
    return '$' + s.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function all(sel) {
    try { return Array.prototype.slice.call(document.querySelectorAll(sel)); }
    catch (e) { return []; }
  }

  function setText(el, text) { if (el && typeof text === 'string' && text) el.textContent = text; }
  function show(el, on) { if (el) el.style.display = on ? '' : 'none'; }

  // A bar carried by an element the page already has. `create` allows one to be made
  // when the page has no such element — that is how an administrator can put an
  // announcement up without anybody editing HTML.
  // ------------------------------------------------------------------ the look
  // What a developer may move, and how far. These limits are the ones admin_api.py
  // enforces; they are repeated here because a value that arrives outside them means
  // the answer did not come from our server, and the page is better off as authored.
  var LIMITS = { fontScale: [0.8, 1.6], spacing: [0.6, 1.8], lineHeight: [1.1, 2.2] };
  var COLOUR = /^(#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})|rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(,\s*(0|1|0?\.\d{1,3})\s*)?\))$/;
  // Six plain names, mapped onto the token names tokens.css already defines. Setting
  // --brand-400 as well as --accent is what makes the derived tints follow the accent.
  var PALETTE = {
    canvas: ['--canvas'],
    ink: ['--ink'],
    accent: ['--accent', '--brand-400'],
    surface: ['--bg-surface', '--neutral-900'],
    border: ['--border-hairline'],
    muted: ['--fg-muted']
  };

  function num(value, range) {
    var n = Number(value);
    if (value === null || value === undefined || value === '' || !isFinite(n)) return null;
    return (n < range[0] || n > range[1]) ? null : n;   // outside the clamp: ignored
  }

  // The whole developer theme as one stylesheet. Custom properties on :root do the work;
  // the four rules under them are the only places the site does not already read a token.
  function themeCss(theme) {
    if (!theme || typeof theme !== 'object') return '';
    var vars = [], css = '', i, name;
    var font = num(theme.fontScale, LIMITS.fontScale);
    var space = num(theme.spacing, LIMITS.spacing);
    var line = num(theme.lineHeight, LIMITS.lineHeight);
    if (font !== null) vars.push('--font-scale:' + font);
    if (space !== null) vars.push('--space-scale:' + space);
    if (line !== null) vars.push('--line-height:' + line);
    var palette = (theme.palette && typeof theme.palette === 'object') ? theme.palette : {};
    for (var key in PALETTE) {
      if (!Object.prototype.hasOwnProperty.call(PALETTE, key)) continue;
      var colour = palette[key];
      if (typeof colour !== 'string' || !COLOUR.test(colour)) continue;  // not a colour
      for (i = 0; i < PALETTE[key].length; i++) {
        name = PALETTE[key][i];
        vars.push(name + ':' + colour);
      }
    }
    if (!vars.length) return '';
    css = ':root{' + vars.join(';') + '}';
    // The three numbers below are the ones site/style.css is authored with: a 106.25%
    // (17px) root and a 1.06rem body. They are repeated here so a scale of 1 lands on
    // exactly the page as authored instead of shrinking it. style.css wins on
    // specificity either way; --font-scale is the hook that actually moves the type.
    if (font !== null) {
      css += '\nhtml{font-size:calc(106.25% * var(--font-scale))}';
      css += '\nbody{font-size:1.06rem}';
    }
    if (line !== null) css += '\nbody{line-height:var(--line-height)}';
    if (space !== null) {
      css += '\n.section{padding-block:calc(clamp(34px,4.2vw,60px) * var(--space-scale))}';
      css += '\n.wrap{padding-inline:calc(clamp(18px,4vw,32px) * var(--space-scale))}';
      css += '\n.grid{gap:calc(18px * var(--space-scale))}';
    }
    return css;
  }

  // The same custom properties, set straight onto the root element as well as written
  // into the style block. Belt and braces: a page that never gets our stylesheet still
  // reads the values off :root. Every step is guarded, because a document without a
  // documentElement, or an element without setProperty, is a page we leave alone.
  function pinRoot(css) {
    try {
      if (String(css).indexOf(':root{') !== 0) return;
      var el = document.documentElement;
      if (!el || !el.style || typeof el.style.setProperty !== 'function') return;
      var body = css.slice(6, css.indexOf('}'));
      var parts = body.split(';');
      for (var i = 0; i < parts.length; i++) {
        var at = parts[i].indexOf(':');
        if (at <= 0) continue;
        var name = parts[i].slice(0, at);
        if (name.indexOf('--') !== 0) continue;
        el.style.setProperty(name, parts[i].slice(at + 1));
      }
    } catch (e) { /* silent, on purpose */ }
  }

  // One style element, reused. Last in the head, so it wins over tokens.css without
  // anybody needing !important.
  function applyTheme(theme) {
    var css = themeCss(theme);
    if (!css) return 0;
    try {
      pinRoot(css);
      var head = document.head;
      if (!head || typeof head.appendChild !== 'function') return 0;
      var el = all('style[data-bailee-theme]')[0];
      if (!el) {
        el = document.createElement('style');
        el.setAttribute('data-bailee-theme', '1');
        head.appendChild(el);
      }
      el.textContent = css;
      return 1;
    } catch (e) { return 0; }
  }

  // ---------------------------------------------------------------- the labels
  // A rename, done once here instead of in eight files. Links are found by the href
  // they already carry, so no page has to grow an attribute for this to work.
  var NAV_HREF = {
    home: 'index.html', pricing: 'pricing.html', plan: 'plan.html'
  };
  var FOOTER_HREF = {
    executiveSummary: 'plan.html#executive-summary',
    productAndTechnology: 'plan.html#product-and-technology',
    businessModel: 'plan.html#business-model-and-pricing',
    financials: 'plan.html#financial-plan-and-risk-register',
    registry: 'registry.json'
  };

  function relabel(group, hrefs, labels) {
    if (!labels || typeof labels !== 'object') return 0;
    var changed = 0;
    for (var key in hrefs) {
      if (!Object.prototype.hasOwnProperty.call(hrefs, key)) continue;
      var text = labels[key];
      if (typeof text !== 'string' || !text || text.length > 40) continue;
      var els = all('a[href="' + hrefs[key] + '"]')
        .concat(all('[data-config="labels.' + group + '.' + key + '"]'));
      for (var i = 0; i < els.length; i++) {
        // A link with elements inside it is the brand, logo and all. Leave it alone.
        if (els[i].firstElementChild) continue;
        // An opted-out link keeps the words the page author wrote.
        if (els[i].getAttribute && els[i].getAttribute('data-keep-label') !== null) continue;
        els[i].textContent = text;
        changed++;
      }
    }
    return changed;
  }

  // -------------------------------------------------------------- the switches
  // Each widget mount already announces itself with data-widget. Off means hidden,
  // not deleted: the page keeps its shape and one save puts it back.
  var WIDGETS = ['notarize', 'protocol', 'certificate', 'attestation', 'pricing', 'workplace'];

  function applyFeatures(features) {
    if (!features || typeof features !== 'object') return 0;
    var changed = 0, i, j, els;
    for (i = 0; i < WIDGETS.length; i++) {
      if (typeof features[WIDGETS[i]] !== 'boolean') continue;
      els = all('[data-widget="' + WIDGETS[i] + '"]');
      for (j = 0; j < els.length; j++) { show(els[j], features[WIDGETS[i]]); changed++; }
    }
    return changed;
  }

  var BAR_STYLE = 'display:block;margin:0;padding:10px 18px;background:#0d121a;'
    + 'border-bottom:1px solid rgba(58,134,255,.45);color:#F6F8FA;'
    + 'font:400 .9rem/1.4 Poppins,system-ui,sans-serif;text-align:center';

  function banner(key, cfg, cls, create) {
    var b = cfg[key];
    if (!b || typeof b !== 'object') return;
    var els = all('[data-config="' + key + '"]');
    if (!els.length) {
      if (!create || !b.show || !b.text || !document.body) return;  // nothing to show
      var made = document.createElement('div');
      made.setAttribute('data-config', key);
      made.className = cls;
      if (made.style) made.style.cssText = BAR_STYLE;
      document.body.insertBefore(made, document.body.firstChild);
      els = [made];
    }
    for (var i = 0; i < els.length; i++) {
      setText(els[i], b.text);
      show(els[i], b.show !== false && !!(b.text || els[i].textContent));
    }
  }

  // Apply a config object to the page. Returns the number of elements it changed.
  function apply(cfg) {
    if (!cfg || typeof cfg !== 'object') return 0;
    var changed = 0, i, els;

    els = all('[data-config="headline"]');
    for (i = 0; i < els.length; i++) { setText(els[i], cfg.headline); changed++; }
    els = all('[data-config="subline"]');
    for (i = 0; i < els.length; i++) { setText(els[i], cfg.subline); changed++; }

    if (typeof cfg.contactEmail === 'string' && cfg.contactEmail.indexOf('@') > 0) {
      els = all('[data-config="contactEmail"]');
      for (i = 0; i < els.length; i++) {
        var el = els[i];
        if (String(el.tagName || '').toUpperCase() === 'A') {
          el.setAttribute('href', 'mailto:' + cfg.contactEmail);
        }
        // Only rewrite the words if the words were an address. "Request a demo" stays.
        if (String(el.textContent || '').indexOf('@') > 0) el.textContent = cfg.contactEmail;
        changed++;
      }
    }

    if (cfg.pricing && typeof cfg.pricing === 'object') {
      for (var key in cfg.pricing) {
        if (!Object.prototype.hasOwnProperty.call(cfg.pricing, key)) continue;
        var text = money(cfg.pricing[key]);
        if (text === null) continue;
        els = all('[data-config="pricing.' + key + '"]');
        for (i = 0; i < els.length; i++) { els[i].textContent = text; changed++; }
      }
    }

    var features = (cfg.features && typeof cfg.features === 'object') ? cfg.features : {};
    banner('demoBanner', cfg, 'stage', false);
    banner('announcement', cfg, 'site-announcement', true);
    if (cfg.maintenance === true) {
      banner('maintenance', { maintenance: { show: true,
        text: 'This service is under maintenance. Verification is unaffected.' } },
        'site-announcement', true);
    }

    // The developer section. Each piece checks its own values and skips what it does not
    // recognise, and the lot is wrapped once more so a surprise here can never stop the
    // words above from having been applied.
    try {
      changed += applyTheme(cfg.theme);
      if (cfg.labels && typeof cfg.labels === 'object') {
        changed += relabel('nav', NAV_HREF, cfg.labels.nav);
        changed += relabel('footer', FOOTER_HREF, cfg.labels.footer);
      }
      changed += applyFeatures(features);
    } catch (e) { /* silent, on purpose */ }
    return changed;
  }

  // Try each source in turn. The first readable answer wins; if none answers, the page
  // is left exactly as it was authored.
  function load() {
    var list = sources();
    if (typeof fetch !== 'function' || !list.length) return Promise.resolve(null);
    var i = 0;
    function next() {
      if (i >= list.length) return null;
      var url = list[i++];
      return fetch(url, { cache: 'no-store' })
        .then(function (res) { if (!res.ok) throw new Error('HTTP ' + res.status); return res.json(); })
        .then(function (cfg) { apply(cfg); return cfg; })
        .catch(function () { return next(); });
    }
    try { return Promise.resolve(next()); } catch (e) { return Promise.resolve(null); }
  }

  root.Bailee.config = { apply: apply, load: load, sources: sources, money: money,
    themeCss: themeCss, limits: LIMITS };

  // Auto-run in a browser only. In node (the acceptance test) it stays a library.
  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { load(); });
    } else { load(); }
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
