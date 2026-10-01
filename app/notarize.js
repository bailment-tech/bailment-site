(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const { sha256, commit, hex, unhex, randomNonce, verifyCommit } = root.Bailee.crypto;
  const { mount, $, esc, wireCopy, monoBlock, row, nowISO, fmtDate,
    wmField, wmValue, wmSet, wireFields } = root.Bailee.ui;

  // Document Record — notarize demo.
  // The file is read with the browser's own File API and hashed with WebCrypto.
  // There is no server in this page: nothing is uploaded, and nothing can be.
  const DISPOSITIONS = [
    ['transmitted', 'Transmitted to client'],
    ['filed', 'Filed with the court'],
    ['executed', 'Executed original'],
    ['received', 'Received from client'],
    ['destroyed', 'Destroyed on schedule (tombstone)'],
  ];

  // Sample documents, offered rather than typed in for you. The list ends with
  // "Write my own", and clicking the box is the same thing.
  const SAMPLE_TEXTS = [
    'RETAINER AGREEMENT \u2014 Doe v. Acme Holdings, executed 14 September 2026.',
    'SETTLEMENT AGREEMENT \u2014 John Client v. Calder Freight, executed 2 August 2026.',
    'EXPERT REPORT \u2014 In re Vantage Data Systems, served 21 July 2026.',
  ];

  // The whole product in one function: digest -> salted commitment -> on-chain record.
  // commit() binds the 32-byte document digest under a fixed 32-byte nonce, the same
  // construction document_record.compact uses, so the commitment opens to exactly one
  // document (C-02).
  async function notarizeBytes(content, nonce, disposition, timestamp = nowISO()) {
    const digest = await sha256(content);
    const c = await commit(content, nonce);
    return {
      digest: hex(digest),
      commitment: hex(c),
      disposition,
      timestamp,
      bytes: content.length,
    };
  }


  // ------------------------------------------------------------------ x402
  // The 402 used to be the end of the road: the server quoted a price and nothing on
  // either side could act on it. It can now be paid. This is the client half of steps
  // 3 to 5 — read the terms, pay them in your own wallet, come back with the hash.
  //
  // THIS IS NOT A WALLET. There is no CIP-30 here and there is not going to be: this
  // page never holds a key, never signs anything, and never asks a wallet to. It shows
  // you the address and the amount, you move the money yourself, and you paste the
  // transaction hash back. The mechanism is what is being demonstrated.
  //
  // The appliance, not a cloud. The default is the one a reader running the backend
  // beside this page already has; anything else typed in is their own deployment.
  const PAY_BASE = 'http://127.0.0.1:8402';

  // Everything a human needs in order to pay, pulled out of the server's own 402. The
  // amount is carried twice on purpose: the display form is what a wallet wants typed
  // into it, and the base units are what the server actually counts.
  function payTerms(body) {
    const b = body || {};
    const t = (b.accepts && b.accepts[0]) || {};
    const s = b.settlement || {};
    const units = Number(s.amountBaseUnits || t.maxAmountRequired || 0) || 0;
    return {
      network: s.network || t.network || '',
      asset: s.asset || t.asset || '',
      assetName: s.assetName || (t.extra && t.extra.name) || '',
      payTo: s.payTo || t.payTo || '',
      amountBaseUnits: units,
      amount: baseUnits(units, (t.extra && t.extra.decimals) || 6),
      priceUsd: t.amount || '',
      header: s.header || 'X-PAYMENT: <64-hex transaction hash>',
      detail: s.detail || '',
      message: b.message || '',
      error: b.error || '',
      receipt: s.receipt || '',
    };
  }

  // 25000000 -> '25.000000'. Done here rather than trusted from the server, because this
  // is the string a reader is about to paste into a wallet and send real money with.
  function baseUnits(units, decimals) {
    const d = Math.max(0, Number(decimals) || 0);
    const n = String(Math.max(0, Math.trunc(Number(units) || 0)));
    if (!d) return n;
    const padded = n.padStart(d + 1, '0');
    return padded.slice(0, padded.length - d) + '.' + padded.slice(padded.length - d);
  }

  // The terms, as a thing a person can act on: two values, each with its own copy
  // button, because an address retyped by hand is money sent to nobody.
  function payTermsHTML(t) {
    return `<div class="nt-pay">
      <h3>Payment required &mdash; 402</h3>
      <p class="nt-pay-lede">${esc(t.message || 'This request has not been paid for.')}</p>
      <div class="nt-pay-line">
        <span class="nt-pay-k">Pay this address</span>
        <code class="mono nt-pay-v">${esc(t.payTo)}</code>
        <button type="button" class="btn ghost nt-copy" data-copy="${esc(t.payTo)}"
          >Copy address</button>
      </div>
      <div class="nt-pay-line">
        <span class="nt-pay-k">Send exactly</span>
        <code class="mono nt-pay-v">${esc(t.amount)} ${esc(t.assetName)}</code>
        <button type="button" class="btn ghost nt-copy" data-copy="${esc(t.amount)}"
          >Copy amount</button>
      </div>
      <p class="nt-pay-sub"><span class="chip">${esc(t.network)}</span>
        <span class="chip">${esc(t.amountBaseUnits.toLocaleString('en-US'))}
        ${esc(t.asset)}</span>
        ${t.priceUsd ? `<span class="chip">$${esc(t.priceUsd)} per document</span>` : ''}</p>
      <p class="nt-pay-sub">Pay it from your own wallet. This page holds no key, signs
        nothing, and never asks your wallet to sign &mdash; it is showing you the terms.
        When the transaction is <strong>in a block</strong>, paste its hash below. A
        transaction that has been submitted but not yet confirmed is not payment yet.</p>
      <div class="field nt-pay-tx">
        <label for="nt-tx">Transaction hash</label>
        <input type="text" id="nt-tx" class="mono" placeholder="64 hexadecimal characters"
          autocomplete="off" spellcheck="false">
      </div>
      <div class="actions">
        <button class="btn" id="nt-retry">Retry with this payment</button>
      </div>
      <p class="wm-hint">Sent back as <code>${esc(t.header)}</code>. One transaction
        settles exactly one charge, ever: the hash is public, so anybody could read it
        off an explorer, and the server refuses a second use of it.</p>
    </div>`;
  }

  // What settled. Plain, specific, and checkable by anyone: the receipt endpoint needs
  // no key, so the reader can go and confirm the appliance agrees with the chain.
  function settledHTML(s, base) {
    if (!s || s.status !== 'settled') return '';
    const url = String(base || PAY_BASE).replace(/\/+$/, '') + '/v1/payments/' + s.txHash;
    return `<div class="nt-settled">
      <p><span class="mark">\u2713</span> <strong>Settled on chain.</strong>
      ${esc(s.amount)} reached <code class="mono">${esc(s.payTo)}</code> on
      ${esc(s.network)}, ${esc(String(s.confirmations))}
      confirmation${s.confirmations === 1 ? '' : 's'} deep, and released one
      notarisation.</p>
      ${monoBlock(s.txHash, 'transaction')}
      <p class="wm-hint">Verified by reading the transaction, not by trusting the header:
      the server summed the outputs to that address in that asset and nothing else.
      Anyone may check it &mdash; <code>GET ${esc(url)}</code> needs no key. That
      transaction cannot settle a second charge here.</p>
    </div>`;
  }

  // A payment the server refused. It repeats the server's own words rather than
  // inventing kinder ones: an underpayment, a replay and a Blockfrost outage are three
  // different problems and a reader told "payment failed" would treat them the same.
  function payRefusedHTML(body, status) {
    const b = body || {};
    return `<div class="nt-pay-bad">
      <p><strong>Not settled.</strong> ${esc(b.message || 'The appliance refused that payment.')}</p>
      <p class="wm-hint">HTTP ${esc(String(status))}${b.error ? ' \u00b7 ' + esc(b.error) : ''}.
      Nothing was recorded and nothing was charged.</p>
    </div>`;
  }

  // The call. Returns the status and the server's own body whatever came back, because
  // the server's words are better than anything this page could invent: the 402 carries
  // the terms, the 409 names the earlier settlement, the 502 says the check did not run.
  async function runNotarize(o) {
    const opts = o || {};
    const f = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!f) {
      return { status: 0, body: { error: 'no_fetch',
        message: 'This page has no network access, so nothing could be sent.' } };
    }
    const base = String(opts.base || PAY_BASE).replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (opts.key) headers.Authorization = 'Bearer ' + opts.key;
    // Only ever set when there is one. An empty X-PAYMENT is not a payment and must not
    // read as an attempt to make one.
    const tx = String(opts.payment || '').trim().toLowerCase();
    if (tx) headers['X-PAYMENT'] = tx;
    let res;
    try {
      res = await f(base + '/v1/notarize', {
        method: 'POST', headers: headers, cache: 'no-store',
        body: JSON.stringify({
          documentDigest: opts.digest || '',
          disposition: opts.disposition || 'transmitted',
          nonce: opts.nonce || '',
        }),
      });
    } catch (err) {
      return { status: 0, body: { error: 'unreachable',
        message: 'The appliance at ' + base + ' did not answer (' + err.message + '). '
          + 'Start the backend, or read the terms and pay them by hand.' } };
    }
    let body = null;
    try { body = await res.json(); } catch (err) { body = null; }
    if (!body || typeof body !== 'object') {
      body = { error: 'unreadable',
        message: 'The appliance answered HTTP ' + res.status + ' with something this '
          + 'page could not read.' };
    }
    return { status: res.status, body: body };
  }

  function ntState() {
    return { content: null, name: '', nonce: randomNonce(32), record: null, terms: null };
  }

  function ntChainVsLocal(s, rec) {
    return `
    <div class="cols">
      <div class="panel chain">
        <h3>Goes on chain</h3>
        ${row('Commitment', `<code>${esc(rec.commitment)}</code>`, 'mono')}
        ${row('Disposition', esc((DISPOSITIONS.find((d) => d[0] === rec.disposition) || [, rec.disposition])[1]))}
        ${row('Timestamp', esc(rec.timestamp))}
        <p class="note">That is the entire public record. 32 bytes, a word, and a time.
        A reader learns that <em>something</em> was notarised. Not what, not by whom,
        not for which client.</p>
      </div>
      <div class="panel local">
        <h3>Never leaves this device</h3>
        ${row('File', esc(s.name || 'typed text'))}
        ${row('Size', rec.bytes.toLocaleString('en-US') + ' bytes')}
        ${row('SHA-256 of the file', `<code>${esc(rec.digest)}</code>`, 'mono')}
        ${row('Matter nonce (salt)', `<code>${esc(hex(s.nonce))}</code>`, 'mono')}
        ${row('File bytes', '<span class="muted">held in this tab only</span>')}
        <p class="note">The nonce is why the commitment is safe to publish. Without it,
        a one-page form off a known template could be guessed and hash-matched.
        Lose the nonce and the commitment becomes unopenable &mdash; it is matter key material.</p>
      </div>
    </div>`;
  }


  // The optional second half of the page. Everything above this line happens in the tab
  // and touches no server at all; this box is the only thing here that leaves it, it is
  // opt-in, and what it sends is named exactly: the 32-byte commitment inputs, never the
  // file. The appliance is the firm's own box, which is the whole point of an appliance.
  function ntSettleHTML() {
    return `<div class="nt-settle" id="nt-settle">
      <h3>Settle it &mdash; x402</h3>
      <p class="wm-hint">Optional, and the only thing on this page that leaves the tab.
      It sends the <strong>digest and the nonce</strong> to an appliance you name so it
      can write the Document Record and sign it. The file itself still never moves. Out
      of balance, the appliance answers <code>402</code> with terms you can actually pay
      &mdash; a real address, on a real testnet, in an asset that exists there.</p>
      <div class="inline">
        <div class="field" style="flex:2 1 220px">
          <label for="nt-base">Appliance</label>
          <input type="text" id="nt-base" class="mono" value="${esc(PAY_BASE)}">
        </div>
        <div class="field" style="flex:2 1 220px">
          <label for="nt-key">Licence key</label>
          <input type="text" id="nt-key" class="mono" placeholder="blf_lk_..."
            autocomplete="off" spellcheck="false">
        </div>
      </div>
      <div class="actions">
        <button class="btn ghost" id="nt-send">Record it on the appliance</button>
      </div>
      <div id="nt-settle-out"></div>
    </div>`;
  }

  // One handler for the first attempt and for the retry, because they are the same
  // request: the retry is that request with a payment header on it. Two code paths here
  // would be two chances for the paid one to drift from the free one.
  function wireSettle(el, s) {
    const box = $(el, '#nt-settle');
    if (!box) return;
    const out = $(el, '#nt-settle-out');
    const send = async (payment) => {
      if (!s.record) { out.innerHTML = '<p class="bad">Hash a document first.</p>'; return; }
      const base = $(el, '#nt-base').value.trim() || PAY_BASE;
      out.innerHTML = '<p class="muted">Asking ' + esc(base) + '\u2026</p>';
      const r = await runNotarize({
        base: base, key: $(el, '#nt-key').value.trim(),
        digest: s.record.digest, disposition: s.record.disposition,
        nonce: hex(s.nonce), payment: payment,
      });
      if (r.status === 200) {
        out.innerHTML = settledHTML(r.body.settlement, base)
          || `<div class="nt-settled"><p><span class="mark">\u2713</span>
              <strong>Recorded.</strong> Charged $0.01 to this licence; nothing
              was settled on chain.</p></div>`;
      } else if (r.status === 402 && !payment) {
        s.terms = payTerms(r.body);
        out.innerHTML = payTermsHTML(s.terms);
      } else if (r.status === 402 || r.status === 409) {
        out.innerHTML = payRefusedHTML(r.body, r.status)
          + (s.terms ? payTermsHTML(s.terms) : '');
      } else {
        out.innerHTML = payRefusedHTML(r.body, r.status);
      }
      wireCopy(out);
    };
    box.addEventListener('click', (e) => {
      const t = e.target;
      if (!t || !t.id) return;
      if (t.id === 'nt-send') send('');
      if (t.id === 'nt-retry') {
        const tx = ($(el, '#nt-tx') || { value: '' }).value.trim();
        if (!tx) { return; }
        send(tx);
      }
    });
  }

  function ntRender(el) {
    const s = ntState();
    el.innerHTML = `
      <h2>Notarize a document</h2>
      <p class="lede">Pick any file. It is hashed <strong>in this browser</strong> with WebCrypto,
      salted with the matter nonce, and turned into a commitment. The file is never uploaded &mdash;
      there is no upload path in this page at all. Check the network tab if you do not believe it:
      every file this page loads comes from bailment.tech.
    <span class="chip on">demo</span> The hashing and the commitment are real; nothing is written
    to a chain yet.</p>

      <div class="panel builder">
        <div class="inline">
          <div class="field" style="flex:2 1 260px">
            <label for="nt-file">Document</label>
            <input type="file" id="nt-file">
          </div>
          ${wmField({ id: 'nt-disp', label: 'Disposition',
            options: DISPOSITIONS.map((d) => ({ value: d[0], label: d[1] })) })}
        </div>
        ${wmField({ id: 'nt-text', label: '\u2026or pick some text instead (no file needed to try this)',
          options: SAMPLE_TEXTS, multiline: true, rows: 3,
          help: 'Nothing here is your document. Choose a sample, or write my own and paste '
            + 'whatever you like \u2014 it is hashed in this tab either way.' })}
        <div class="field">
          <label for="nt-nonce">Matter nonce (32 random bytes, generated here)</label>
          <input type="text" id="nt-nonce" class="mono" value="${hex(s.nonce)}">
        </div>
        <div class="actions">
          <button class="btn" id="nt-go">Hash &amp; commit</button>
          <button class="btn ghost" id="nt-new">New nonce</button>
          <button class="btn ghost" id="nt-check" disabled>Re-check commitment</button>
        </div>
      </div>
      <div id="nt-out"></div>`;

    const out = $(el, '#nt-out');
    const nonceInput = $(el, '#nt-nonce');
    wireCopy(el);
    wireFields(el);

    $(el, '#nt-file').addEventListener('change', async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      s.content = new Uint8Array(await f.arrayBuffer());
      s.name = f.name;
      // The file wins: empty the text field rather than leaving a sample standing in it.
      wmSet(el, 'nt-text', '');
      out.innerHTML = `<p class="muted">Loaded <strong>${esc(f.name)}</strong>
        (${f.size.toLocaleString('en-US')} bytes) into this tab. Press <em>Hash &amp; commit</em>.</p>`;
    });

    $(el, '#nt-new').addEventListener('click', () => {
      s.nonce = randomNonce(32);
      nonceInput.value = hex(s.nonce);
    });

    $(el, '#nt-go').addEventListener('click', async () => {
      const typed = wmValue(el, 'nt-text');
      if (typed.trim()) { s.content = new TextEncoder().encode(typed); s.name = ''; }
      if (!s.content) { out.innerHTML = '<p class="bad">Pick a file or type some text first.</p>'; return; }
      try { s.nonce = unhex(nonceInput.value.trim()); }
      catch { out.innerHTML = '<p class="bad">The nonce must be hex.</p>'; return; }
      // Exactly 32 bytes, never fewer and never more: a fixed-width nonce is what stops
      // one commitment opening to two documents (C-02). Say so here rather than letting
      // commit() throw into the console.
      if (s.nonce.length !== 32) {
        out.innerHTML = `<p class="bad">The nonce must be exactly 32 bytes
          (64 hex characters) &mdash; this one is ${s.nonce.length}. A variable-length nonce
          would let the commitment be opened to more than one document.</p>`;
        return;
      }
      s.record = await notarizeBytes(s.content, s.nonce, wmValue(el, 'nt-disp'));
      out.innerHTML = ntChainVsLocal(s, s.record) + `
        <p class="note">Published ${esc(fmtDate(s.record.timestamp))} to the matter's own contract.
        Either party may do this: the privilege belongs to the client, so a client can notarize
        over the firm's objection. Notarizing cannot be undone.</p>
        <div id="nt-recheck"></div>` + ntSettleHTML();
      $(el, '#nt-check').disabled = false;
      wireCopy(out);
      wireSettle(out, s);
    });

    $(el, '#nt-check').addEventListener('click', async () => {
      if (!s.record) return;
      const okc = await verifyCommit(s.content, s.nonce, unhex(s.record.commitment));
      const slot = $(el, '#nt-recheck') || out;
      slot.innerHTML = `<div class="verdict ${okc ? 'pass' : 'fail'}">
        <span class="mark">${okc ? '\u2713' : '\u2717'}</span>
        <span><strong>${okc ? 'Commitment re-derived from the file' : 'Mismatch'}</strong>
        ${okc ? 'Holder of the file plus the nonce can prove the published commitment is this document. Nobody else can.'
              : 'The file or the nonce is not the one that produced this commitment.'}</span></div>`;
    });
  }

  mount('notarize', ntRender);

  root.Bailee.notarize = { DISPOSITIONS, SAMPLE_TEXTS, notarizeBytes,
    PAY_BASE, payTerms, baseUnits, payTermsHTML, settledHTML, payRefusedHTML,
    runNotarize, ntSettleHTML };
})(typeof globalThis !== 'undefined' ? globalThis : this);
