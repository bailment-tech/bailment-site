(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const { sha256, hex, generateSigningKey, signJSON, verifyJSON, exportPublicKey, importPublicKey, importPrivateKey, keyFingerprint, b64url, unb64url, utf8Decode, canonical, generateReaderKey, readerCode, importReaderCode, seal, unseal } = root.Bailee.crypto;
  const { mount, $, esc, wireCopy, monoBlock, row, nowISO, fmtDate, short,
    loadRegistry, registrySigner, wmField, wmValue, wireFields } = root.Bailee.ui;

  // Attestation: a sentence a judge can read, bound to a digest a machine can check.
  // Recipient, purpose and expiry sit INSIDE the signature, so a proof handed to one
  // reader for one purpose cannot be quietly reused for another.
  const ATT_TYPE = 'bailment.ai/attestation/v1';

  // Demo choices, not facts. Nothing is pre-typed into a box: each of these is a
  // dropdown whose last option is "Write my own".
  const ATT_OPTIONS = {
    recipient: ['Hon. J. L. Robart', 'Opposing counsel of record', 'Clerk of the Court'],
    purpose: ['In camera authenticity review', 'Authentication of an exhibit for filing',
      'Settlement conference disclosure'],
    signer: ['Kevin G. Mohr, Esq.', 'Miriam A. Vale', 'Theo Okonkwo'],
    bar: ['Bar No. 123456', 'CA SBN 302914', 'NY 5512883'],
  };

  function statementOptions() {
    return [
      defaultStatement('retainer agreement', 'Doe v. Acme Holdings', '2026-09-14'),
      defaultStatement('executed settlement agreement', 'John Client v. Calder Freight', '2026-08-02'),
      defaultStatement('expert report', 'In re Vantage Data Systems', '2026-07-21'),
    ];
  }

  function defaultStatement(what, matter, when) {
    return `The document bearing this digest is the ${what} transmitted in ${matter} on `
      + `${fmtDate(when)}, and I have compared the copy provided against the record of transmission.`;
  }

  async function buildAttestation(f) {
    return {
      type: ATT_TYPE,
      tier: 1,
      statement: f.statement,
      document: { digest: f.digest },
      recipient: f.recipient,
      purpose: f.purpose,
      issuedAt: f.issuedAt || nowISO(),
      expiry: f.expiry,
      signer: { name: f.signerName, barNumber: f.signerBar, jurisdiction: f.signerJurisdiction },
    };
  }

  async function signAttestation(att, keys) {
    return {
      k: 'attestation',
      att,
      sig: await signJSON(keys.privateKey, att),
      pub: await exportPublicKey(keys.publicKey),
    };
  }


  // The attorney demo key. Its public half is in registry.json, so an attestation the
  // demo signs comes back as a pass. The private half is printed here for anyone to
  // take — which is the point: a key anyone can use says nothing about who signed.
  // A real attorney key is generated on the firm's own appliance and never leaves it.
  const DEMO_ATTORNEY = {
    id: 'demo-attorney-mohr',
    spki: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2taL90NN8ctbfzJhGxVeisUPb7lyIT6VePWOA7sLAxULixRitelCWqvsGN06dO_1BUdEcEriOyG4AnvNy2N32w',
    pkcs8: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiY_rwfhca5RXLkwfnpqHZQzB1IQsrgn5MTIqx7TirzmhRANCAATa1ov3Q03xy1t_MmEbFV6KxQ9vuXIhPpV49Y4DuwsDFQuLFGK16UJaq-wY3Tp07_UFR0RwSuI7IbgCe83LY3fb',
  };

  let demoKeysPromise = null;
  function demoSigningKeys() {
    if (!demoKeysPromise) {
      demoKeysPromise = (async () => ({
        privateKey: await importPrivateKey(DEMO_ATTORNEY.pkcs8),
        publicKey: await importPublicKey(DEMO_ATTORNEY.spki),
      }))();
    }
    return demoKeysPromise;
  }

  const HEX64 = /^[0-9a-f]{64}$/i;
  const MAX_TEXT = 4000;
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';
  const parses = (v) => nonEmpty(v) && !isNaN(new Date(v));

  // Shape before trust. A payload that fails here is reported as "not readable"; it is
  // never half-checked and never rendered as though something had been proved.
  function attestationShapeError(payload) {
    if (!isObj(payload)) return 'That is not an attestation payload.';
    const { att, sig, pub } = payload;
    if (!isObj(att) || att.type !== ATT_TYPE) return 'Not a Bailee attestation.';
    if (!nonEmpty(sig) || !nonEmpty(pub)) return 'The signature or the public key is missing.';
    if (!nonEmpty(att.statement)) return 'There is no statement. An attestation is a sentence a person can read.';
    if (att.statement.length > MAX_TEXT) return 'The statement is too long to be an attestation.';
    if (!isObj(att.document) || !HEX64.test(String(att.document.digest || ''))) {
      return 'No document digest. An attestation bound to no document attests to nothing.';
    }
    if (!nonEmpty(att.recipient)) return 'No recipient. An attestation with no named reader has no scope.';
    if (!nonEmpty(att.purpose)) return 'No purpose. An attestation with no stated purpose has no scope.';
    if (!parses(att.issuedAt)) return 'The issue date is missing or unreadable.';
    if (!parses(att.expiry)) return 'No expiry, or an unreadable one. An attestation that never stops being good is refused.';
    if (!isObj(att.signer) || !nonEmpty(att.signer.name)) return 'The signer block is missing.';
    return null;
  }

  function attEncode(p) { return b64url(new TextEncoder().encode(JSON.stringify(p))); }
  function attDecode(s) { return JSON.parse(utf8Decode(unb64url(String(s).trim().replace(/^.*#(?:[ca]=)?/, '')))); }
  function attestationURL(p, base = 'verify.html') { return `${base}#a=${attEncode(p)}`; }

  // A verifier that explains itself. Three outcomes, never two:
  //   'verified'     signed by a key in the registry, addressed to the reader who asked,
  //                  in date, and nothing contradicted
  //   'unregistered' the arithmetic checks out, but the key is not one we can name
  //   'unscoped'     the arithmetic checks out, but the reader has not said who they are,
  //                  so "issued to you" cannot be tested
  //   'fail'         a check failed
  //   'unreadable'   not an attestation we can read
  // `ok` is true only for 'verified'. Nothing inside the payload can move it there.
  //
  // opts: { reader, purpose, digest, now, registry }. `reader` and `purpose` are what the
  // person in front of the screen asserts; they are never taken from the payload.
  async function verifyAttestation(payload, opts = {}) {
    const o = opts || {};
    const now = o.now ? new Date(o.now) : new Date();

    const shapeError = attestationShapeError(payload);
    if (shapeError) {
      return { ok: false, status: 'unreadable', state: 'fail', quarantine: true,
        fatal: shapeError, headline: 'Not readable', findings: [] };
    }

    const { att, sig, pub } = payload;
    let key;
    try { key = await importPublicKey(pub); }
    catch {
      return { ok: false, status: 'unreadable', state: 'fail', quarantine: true,
        fatal: 'The public key in this payload is not a readable P-256 key.',
        headline: 'Not readable', findings: [] };
    }
    const fingerprint = await keyFingerprint(pub);
    const signature = await verifyJSON(key, sig, att);
    const findings = [];
    // Nothing gets a tick once the signature has failed: the fields are then just text.
    const lv = (level) => (signature || level !== 'ok' ? level : 'warn');
    const lb = (label) => (signature ? label : 'Unsigned text only \u2014 ' + label);

    findings.push(signature
      ? { level: 'ok', label: 'Signature valid',
          detail: `The statement, the digest and every scope field below were signed by the key with `
            + `fingerprint ${fingerprint}, and none of them has changed since.` }
      : { level: 'bad', label: 'Signature invalid',
          detail: 'The statement, the digest or one of the scope fields was changed after signing. '
            + 'Nothing in this file was checked.' });

    // --- who holds the key. From registry.json, never from the payload.
    const loaded = o.registry ? { registry: o.registry, source: 'supplied', error: null } : await loadRegistry();
    const signer = registrySigner(loaded.registry, {
      spki: pub, fingerprint, at: att.issuedAt, signs: 'attestation' });
    const registered = !!(signer && signer.live && signature);
    const claimed = `${att.signer.name}${att.signer.barNumber ? ` (${att.signer.barNumber})` : ''}`;
    let signerNameMatch = null;

    if (signer && signer.live) {
      signerNameMatch = String(att.signer.name).trim().toLowerCase() === String(signer.name || '').trim().toLowerCase()
        && (!signer.barNumber || String(att.signer.barNumber || '').trim().toLowerCase()
            === String(signer.barNumber).trim().toLowerCase());
      findings.push(!signature
        ? { level: 'warn', label: `Key ${fingerprint} is listed in the registry, but it did not sign this`,
            detail: 'The key this file carries is a registered one, and the signature still failed. Either the '
              + 'file was altered after signing, or the key was copied from somewhere it does belong. Nothing '
              + 'here was signed by its registered holder.' }
        : signerNameMatch
        ? { level: 'ok', label: `Signed by ${signer.name}${signer.barNumber ? ` (${signer.barNumber})` : ''}`,
            detail: `Key ${fingerprint} is registered to that attorney at ${signer.firm}, valid `
              + `${fmtDate(signer.window.from)} to ${fmtDate(signer.window.until)}. Read from ${loaded.source}.` }
        : { level: 'bad', label: 'The file names a different signer from the registry',
            detail: `The file says it was signed by ${claimed}. The registry records key ${fingerprint} to `
              + `${signer.name}${signer.barNumber ? ` (${signer.barNumber})` : ''}. One of the two is wrong.` });
    } else if (signer) {
      findings.push({ level: 'bad', label: 'Signing key is registered, but not for this date',
        detail: `Key ${fingerprint} was valid ${fmtDate(signer.window.from)} to ${fmtDate(signer.window.until)}. `
          + 'This attestation is dated outside that window.' });
    } else {
      findings.push({ level: 'warn', label: `Signed by key ${fingerprint}, which is not in the registry`,
        detail: `That key travelled with this file, so this page cannot tell you whose it is. The file claims `
          + `${claimed}; that is text inside the file, not a name anyone here confirmed. Anybody can make a key `
          + 'and put any name beside it.' });
    }

    // --- recipient. The reader says who they are; an unasserted reader is never a pass.
    const reader = String(o.reader || '').trim();
    const recipientMatch = reader ? reader.toLowerCase() === String(att.recipient).trim().toLowerCase() : null;
    if (!reader) {
      findings.push({ level: 'info', label: `Addressed to ${att.recipient}`,
        detail: 'You have not told this verifier who you are, so it cannot check that the attestation was issued '
          + 'to you. Until you do, this cannot be a pass.' });
    } else if (recipientMatch) {
      findings.push({ level: lv('ok'), label: lb(`Issued to you (${att.recipient})`),
        detail: 'You typed that name yourself. The binding is evidentiary, not technical: the signer fixed the '
          + 'name, nothing here proves you are that person.' });
    } else {
      findings.push({ level: 'bad', label: `Issued to ${att.recipient}, not to you`,
        detail: `You identified yourself as ${reader}. This proof was aimed at one named reader; `
          + 'it is not evidence in your hands.' });
    }

    // --- purpose. Checked against a purpose the reader states, or reported as a plain fact.
    const purpose = String(o.purpose || '').trim();
    const purposeMatch = purpose ? purpose.toLowerCase() === String(att.purpose).trim().toLowerCase() : null;
    if (!purpose) {
      findings.push({ level: 'info', label: `This proof was issued for: ${att.purpose}`,
        detail: 'You have not said what you are using it for, so nothing was compared. A purpose inside the '
          + 'signature records what was intended; it does not stop anyone reusing the proof elsewhere.' });
    } else if (purposeMatch) {
      findings.push({ level: lv('ok'), label: lb(`Purpose matches: ${att.purpose}`),
        detail: 'What you said you are using this for is what it was issued for.' });
    } else {
      findings.push({ level: 'bad', label: `Issued for ${att.purpose}, not for ${purpose}`,
        detail: 'Use outside what was signed is outside what the signer stood behind.' });
    }

    // --- expiry. Required by the shape check above, so there is always a window.
    const exp = new Date(att.expiry);
    const expired = now > exp;
    if (expired) {
      findings.push({ level: 'bad', label: `Expired on ${fmtDate(att.expiry)}`,
        detail: 'The signature is still mathematically valid; the attestation is not. Ask the signer to reissue.' });
    } else {
      const days = Math.ceil((exp - now) / 864e5);
      findings.push({ level: lv('ok'), label: lb(`Valid until ${fmtDate(att.expiry)}`), detail: `${days} day(s) remaining.` });
    }

    // --- document binding, only the reader can supply the other half.
    let digestMatch = null;
    if (o.digest && String(o.digest).trim()) {
      digestMatch = String(o.digest).trim().toLowerCase() === String(att.document.digest).toLowerCase();
      findings.push(digestMatch
        ? { level: lv('ok'), label: lb('Your copy matches the attested digest'), detail: att.document.digest }
        : { level: 'bad', label: 'Your copy is NOT the attested document',
            detail: `attested ${att.document.digest}\nyours    ${String(o.digest).trim()}` });
    } else {
      findings.push({ level: 'info', label: 'Not checked against your copy',
        detail: `This attestation is bound to the document with digest ${att.document.digest}. Paste the digest `
          + 'of the copy in your hand and it will be compared. Until then, this could be about a different file.' });
    }

    const broken = !signature || expired || digestMatch === false || recipientMatch === false
      || purposeMatch === false || signerNameMatch === false || !!(signer && !signer.live);
    let status, state, headline;
    if (broken) {
      status = 'fail'; state = 'fail'; headline = 'Attestation does not hold';
    } else if (!registered) {
      status = 'unregistered'; state = 'open'; headline = 'Consistent but unregistered';
    } else if (recipientMatch !== true) {
      status = 'unscoped'; state = 'open'; headline = 'Consistent, but not shown to be yours';
    } else {
      status = 'verified'; state = 'pass'; headline = 'Attestation holds for you';
    }

    return { ok: status === 'verified', status, state, headline, quarantine: signature !== true,
      signature, fingerprint, registered, registeredSigner: signer, signerNameMatch, claimedSigner: claimed,
      registrySource: loaded.source, registryError: loaded.error,
      expired, recipientMatch, purposeMatch, digestMatch, findings, att };
  }

  // --------------------------------------------------- tier 2: sealed

  // Same signed payload, encrypted to the reader's single-use public code.
  // There is no key directory: the reader makes the key in their own browser.
  async function sealAttestation(payload, code) {
    const pub = await importReaderCode(code);
    const env = await seal(new TextEncoder().encode(JSON.stringify(payload)), pub);
    return { ...env, tier: 2 };
  }

  async function openSealed(envelope, readerPrivateKey) {
    return JSON.parse(utf8Decode(await unseal(envelope, readerPrivateKey)));
  }

  // ------------------------------------------------------------------ UI

  const MARK = { ok: '\u2713', bad: '\u2717', warn: '!', info: '\u00b7' };

  function findingsHTML(r) {
    if (r.fatal) return `<div class="verdict fail"><span class="mark">\u2717</span>
      <span><strong>Not readable</strong>${esc(r.fatal)}</span></div>`;

    const sub = r.state === 'pass'
      ? 'Signed by a key the registry names, addressed to you, in date, and nothing contradicted.'
      : r.state === 'open'
        ? (r.status === 'unregistered'
            ? 'The signature checks out and nothing in the file has been altered \u2014 but the key that signed it '
              + 'is not in the registry, so this page cannot tell you whose key it is, or whether the person named '
              + 'below signed anything.'
            : 'The signature checks out and the key is registered \u2014 but you have not told this verifier who '
              + 'you are, so it cannot say this was issued to you.')
        : 'At least one check failed. The detail is below.';

    const head = `<div class="verdict ${r.state === 'pass' ? 'pass' : r.state === 'fail' ? 'fail' : 'open'}"
      ${r.state === 'open' ? 'style="border-color:color-mix(in srgb,var(--tint-ice) 55%,transparent)"' : ''}>
      <span class="mark">${r.state === 'pass' ? '\u2713' : r.state === 'fail' ? '\u2717' : '!'}</span>
      <span><strong>${esc(r.headline)}</strong>${esc(sub)}</span></div>`;

    // The statement is the part a judge reads, so it is the part most worth faking.
    // Signed, it is shown as the signed sentence. Unsigned, it is quarantined: visible,
    // clearly labelled, no tick, no authority borrowed from the page around it.
    const statement = r.signature
      ? `<div class="kv"><span class="k">Statement signed</span>
          <span class="v" style="color:var(--ink)">\u201c${esc(r.att.statement)}\u201d</span></div>`
      : `<div class="panel" style="border-style:dashed;margin:0 0 12px">
          <h3 class="bad">Unverified content \u2014 do not rely on any of it</h3>
          <p class="muted">The signature did not check out, so no one stands behind the words below. They are
          shown only so you can see what the file claims.</p>
          <p class="muted" style="white-space:pre-wrap">\u201c${esc(r.att.statement)}\u201d</p>
        </div>`;

    return head + statement + r.findings.map((f) => `
      <div class="kv"><span class="k ${f.level === 'info' ? 'muted' : esc(f.level)}">${MARK[f.level] || '\u00b7'}
        ${esc(f.label)}</span>
        <span class="v muted" style="white-space:pre-wrap">${esc(f.detail)}</span></div>`).join('');
  }

  function atRender(el, mode) {
    const showBuilder = mode !== 'verify';
    const inTwoWeeks = new Date(Date.now() + 14 * 864e5).toISOString().slice(0, 10);
    el.innerHTML = `
      <h2>Attestation &mdash; public and sealed</h2>
      <p class="lede">The human sentence is what a judge reads. The digest is what the machine checks.
      Neither works without the other. Who it is for, what it is for, and when it expires are
      <strong>inside</strong> the signature, so changing one breaks it — and the verifier then compares
      them against what <em>you</em> say, not against the file. What no signature can do is tell you whose key
      made it; that comes from <code>registry.json</code>, which arrives with this page rather than with the
      proof.</p>
      ${showBuilder ? `
      <div class="panel builder">
        <h3>Tier 1 &mdash; public attestation</h3>
        <div class="field"><label>Document digest (SHA-256)</label>
          <input id="at-digest" class="mono" placeholder="paste from the notarize widget, or leave blank for a demo digest"></div>
        ${wmField({ id: 'at-statement', label: 'Statement', options: statementOptions(),
          multiline: true, rows: 3,
          help: 'The sentence is the attorney\u2019s, not this page\u2019s. Pick one to see the '
            + 'shape, or write the one you would actually sign.' })}
        <div class="inline">
          ${wmField({ id: 'at-recipient', label: 'Recipient', options: ATT_OPTIONS.recipient })}
          ${wmField({ id: 'at-purpose', label: 'Purpose', options: ATT_OPTIONS.purpose })}
          <div class="field"><label>Expires</label><input id="at-expiry" type="date" value="${inTwoWeeks}"></div>
        </div>
        <div class="inline">
          ${wmField({ id: 'at-signer', label: 'Signing attorney', options: ATT_OPTIONS.signer })}
          ${wmField({ id: 'at-bar', label: 'Bar number', options: ATT_OPTIONS.bar })}
        </div>
        <div class="actions"><button class="btn" id="at-issue">Sign attestation</button></div>
        <div id="at-issued"></div>
      </div>` : ''}

      <div class="panel">
        <h3>Verifier</h3>
        <div class="field"><textarea id="at-payload" rows="3" placeholder="verify.html#a=\u2026"></textarea></div>
        <div class="inline">
          ${wmField({ id: 'at-reader', label: 'I am',
            options: [{ value: '', label: '\u2014 nobody has said who is reading \u2014' }]
              .concat(ATT_OPTIONS.recipient) })}
          ${wmField({ id: 'at-purpose-in', label: 'I am using it for',
            options: [{ value: '', label: '\u2014 not stated \u2014' }].concat(ATT_OPTIONS.purpose) })}
          <div class="field"><label>Today's date (try a date after expiry)</label>
            <input id="at-now" type="date" value="${new Date().toISOString().slice(0, 10)}"></div>
          <div class="field"><label>Digest of my copy (optional)</label><input id="at-mydigest" class="mono"></div>
        </div>
        <p class="note">Leave <em>I am</em> blank and this can never be a pass: an attestation is issued to one
        named reader, and a verifier that has not been told who is reading cannot check that. Nobody here can
        prove you are who you type, so the name binding is evidentiary, not technical.</p>
        <div class="actions"><button class="btn ghost" id="at-verify">Verify</button></div>
        <div id="at-result"></div>
      </div>

      <div class="panel">
        <h3>Tier 2 &mdash; sealed to one reader</h3>
        <p>No PKI, no key directory, no reader keys held anywhere. The reader generates a
        single-use keypair in their own browser and reads out a short code. The private half
        never leaves their machine.</p>
        <div class="cols">
          <div>
            <label>1. Reader, in their browser</label>
            <div class="actions" style="margin-top:0"><button class="btn ghost" id="at-genkey">Generate single-use key</button></div>
            <div id="at-code"></div>
          </div>
          <div>
            <label>2. Lawyer, sealing to that code</label>
            <div class="field"><input id="at-codein" class="mono" placeholder="paste or type the reader's code"></div>
            <div class="actions" style="margin-top:0"><button class="btn ghost" id="at-seal">Seal attestation</button></div>
            <div id="at-envelope"></div>
          </div>
        </div>
        <div style="margin-top:14px">${wmField({ id: 'at-openas',
          label: '3. Reader, before opening: I am',
          options: [{ value: '', label: '\u2014 say who you are reading as \u2014' }]
            .concat(ATT_OPTIONS.recipient) })}</div>
        <div class="actions"><button class="btn ghost" id="at-open">3. Reader opens it</button>
          <button class="btn ghost" id="at-openwrong">Try opening with the wrong key</button></div>
        <div id="at-opened"></div>
        <p class="note">Sealing is a lock on the door, not a leash. A reader who opens it can forward what
        they read. And opening the envelope proves only that this browser holds the matching private half —
        it says nothing about who the attestation inside is addressed to, which is why the reader is asked
        separately who they are. That limit is stated in the product, not hidden.</p>
      </div>`;

    wireCopy(el);
    wireFields(el);
    const S = { payload: null, readerKeys: null, code: '', envelope: null };

    async function issue() {
      const g = (id) => $(el, id).value.trim();
      const w = (id) => wmValue(el, id).trim();
      const digest = g('#at-digest') || hex(await sha256('demo retainer agreement \u2014 Doe v. Acme'));
      const keys = await demoSigningKeys();   // the registry's demo attorney key, so the demo shows a real pass
      const att = await buildAttestation({
        statement: w('at-statement'), digest,
        recipient: w('at-recipient'), purpose: w('at-purpose'),
        expiry: new Date(g('#at-expiry') + 'T23:59:59Z').toISOString(),
        signerName: w('at-signer'), signerBar: w('at-bar'), signerJurisdiction: 'Washington',
      });
      S.payload = await signAttestation(att, keys);
      const url = attestationURL(S.payload);
      $(el, '#at-issued').innerHTML = `
        <div class="cols" style="margin-top:14px">
          <div class="panel"><h3>What the reader sees</h3>
            <p style="color:var(--ink)">\u201c${esc(att.statement)}\u201d</p>
            ${row('Digest', `<code>${esc(att.document.digest)}</code>`, 'mono')}
            ${row('Issued to', esc(att.recipient))}
            ${row('Purpose', esc(att.purpose))}
            ${row('Expires', esc(fmtDate(att.expiry)))}
            ${row('Signer', esc(att.signer.name) + ' \u00b7 ' + esc(att.signer.barNumber))}
          </div>
          <div class="panel"><h3>What is signed</h3>
            <p>Every field on the left, as one canonical byte string. Change any of them and the
            signature breaks \u2014 including the recipient and the expiry. This demo signs with the
            <strong>demo attorney key</strong> listed in <code>registry.json</code>; its private half is
            printed in <code>app/attestation.js</code> for anyone to take, which is why a demo pass
            demonstrates the mechanism and proves nothing about who signed.</p>
            ${monoBlock(await keyFingerprint(S.payload.pub), 'Public key fingerprint')}
          </div>
        </div>
        ${monoBlock(url, 'Verification URL')}`;
      $(el, '#at-payload').value = url;
      wireCopy($(el, '#at-issued'));
    }

    if (showBuilder) $(el, '#at-issue').addEventListener('click', issue);

    $(el, '#at-verify').addEventListener('click', async () => {
      try {
        const p = attDecode($(el, '#at-payload').value);
        const now = $(el, '#at-now').value ? new Date($(el, '#at-now').value + 'T12:00:00Z') : new Date();
        const r = await verifyAttestation(p, {
          reader: wmValue(el, 'at-reader'), purpose: wmValue(el, 'at-purpose-in'), now,
          digest: $(el, '#at-mydigest').value.trim() || null,
        });
        $(el, '#at-result').innerHTML = findingsHTML(r);
      } catch (err) {
        $(el, '#at-result').innerHTML = `<p class="bad">${esc(err.message)}</p>`;
      }
    });

    $(el, '#at-genkey').addEventListener('click', async () => {
      S.readerKeys = await generateReaderKey();
      S.code = await readerCode(S.readerKeys.publicKey);
      $(el, '#at-code').innerHTML = `<div class="code-readout">${esc(S.code)}</div>
        <p class="note">Read that aloud, or email it. It is a compressed P-256 public key.
        Nothing is registered anywhere, and it is useless after this one document.</p>`;
      $(el, '#at-codein').value = S.code;
    });

    $(el, '#at-seal').addEventListener('click', async () => {
      try {
        if (!S.payload) await issue();
        const code = $(el, '#at-codein').value.trim();
        if (!code) throw new Error('Generate or paste a reader code first.');
        S.envelope = await sealAttestation(S.payload, code);
        $(el, '#at-envelope').innerHTML = monoBlock(JSON.stringify(S.envelope), 'Sealed envelope \u2014 safe to file or email')
          + '<p class="note">Bailment cannot open this. Nor can the court clerk, nor anyone '
          + 'holding the filing. Only the browser that made the code.</p>';
        wireCopy($(el, '#at-envelope'));
      } catch (err) { $(el, '#at-envelope').innerHTML = `<p class="bad">${esc(err.message)}</p>`; }
    });

    $(el, '#at-open').addEventListener('click', async () => {
      try {
        if (!S.envelope || !S.readerKeys) throw new Error('Seal something first.');
        const p = await openSealed(S.envelope, S.readerKeys.privateKey);
        // The reader's identity comes from the reader, never from p.att.recipient:
        // comparing the payload against itself always matches and proves nothing.
        const r = await verifyAttestation(p, { reader: wmValue(el, 'at-openas') });
        $(el, '#at-opened').innerHTML = '<h3>Opened</h3>'
          + '<p class="note">Decryption says the envelope was sealed to this browser\u2019s key. It says nothing '
          + 'about who the attestation inside is addressed to \u2014 that is the check below.</p>'
          + findingsHTML(r);
      } catch (err) { $(el, '#at-opened').innerHTML = `<p class="bad">${esc(err.message)}</p>`; }
    });

    $(el, '#at-openwrong').addEventListener('click', async () => {
      try {
        if (!S.envelope) throw new Error('Seal something first.');
        const other = await generateReaderKey();
        await openSealed(S.envelope, other.privateKey);
        $(el, '#at-opened').innerHTML = '<p class="bad">It opened. That would be a bug.</p>';
      } catch {
        $(el, '#at-opened').innerHTML = `<div class="verdict pass"><span class="mark">\u2713</span>
          <span><strong>Refused</strong>AES-GCM rejected the wrong key outright. No partial
          plaintext, no error oracle, nothing to grind on.</span></div>`;
      }
    });

    // verify.html#a=<payload> — the signature and the dates are checked straight away, and
    // the file's own words are shown. What is NOT checked is whether it was issued to whoever
    // opened the link, because nobody has said who that is, so this path can never reach a
    // pass. It stops at "consistent, but not shown to be yours".
    const fromHash = (typeof location !== 'undefined' && location.hash.startsWith('#a='))
      ? location.hash : null;
    if (fromHash) {
      $(el, '#at-payload').value = fromHash;
      (async () => {
        try {
          $(el, '#at-result').innerHTML =
            findingsHTML(await verifyAttestation(attDecode(fromHash), { reader: '', purpose: '' }));
        } catch (err) {
          $(el, '#at-result').innerHTML = `<div class="verdict fail"><span class="mark">\u2717</span>
            <span><strong>Not readable</strong>That link does not carry an attestation this page can read.
            ${esc(err.message)}</span></div>`;
        }
      })();
    }
  }

  mount('attestation', atRender);

  root.Bailee.attestation = { ATT_TYPE, ATT_OPTIONS, DEMO_ATTORNEY, demoSigningKeys, attestationShapeError, defaultStatement,
    statementOptions,
    buildAttestation, signAttestation, attEncode, attDecode, attestationURL, verifyAttestation, sealAttestation,
    openSealed };
})(typeof globalThis !== 'undefined' ? globalThis : this);
