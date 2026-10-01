// Self-check. Runs identically in the browser (app/selftest.html) and under node
// (node app/selftest.node.js). Every assertion below exercises real crypto.
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const B = root.Bailee;

  async function run(report) {
    const C = B.crypto;
    let pass = 0, fail = 0;
    const ok = (name, cond, detail) => {
      if (cond) pass++; else fail++;
      report(name, !!cond, detail || '');
    };
    const enc = (s) => new TextEncoder().encode(s);
    const dec = (b) => new TextDecoder().decode(b);
    const group = (t) => report(t, null, '');

    /* ---------------------------------------------------------- encoding */
    group('Encoding');
    const rnd = C.randomNonce(40);
    ok('hex round-trips', C.hex(C.unhex(C.hex(rnd))) === C.hex(rnd));
    ok('base64url round-trips', C.hex(C.unb64url(C.b64url(rnd))) === C.hex(rnd));
    ok('base32 round-trips', C.hex(C.unbase32(C.base32(rnd))) === C.hex(rnd));
    ok('canonical JSON ignores key order',
      C.canonical({ a: 1, b: [2, { d: 4, c: 3 }] }) === C.canonical({ b: [2, { c: 3, d: 4 }] , a: 1 }));

    // C-13. canonical() decides which bytes get signed, so it must refuse anything it
    // cannot represent exactly instead of encoding it as {} or null or a hole.
    const throws = (fn) => { try { fn(); return false; } catch { return true; } };
    ok('canonical() throws on a Date instead of silently signing it as {}',
      throws(() => C.canonical(new Date())));
    ok('canonical() throws on a Map and on a Set',
      throws(() => C.canonical(new Map([['a', 1]]))) && throws(() => C.canonical(new Set([1]))));
    ok('canonical() throws on [1, undefined, 2] instead of emitting the invalid [1,,2]',
      throws(() => C.canonical([1, undefined, 2])));
    ok('canonical() throws on an array hole', throws(() => C.canonical(JSON.parse('[1,2]').concat(new Array(1)))));
    ok('canonical() throws on NaN and on Infinity',
      throws(() => C.canonical({ n: NaN })) && throws(() => C.canonical({ n: Infinity })));
    ok('canonical() throws on undefined, a function and a symbol',
      throws(() => C.canonical(undefined)) && throws(() => C.canonical(() => 1))
        && throws(() => C.canonical(Symbol('s'))));
    ok('canonical() names the path it choked on, so a bad field is findable', (() => {
      try { C.canonical({ att: { expiry: new Date() } }); return false; }
      catch (e) { return /\$\.att\.expiry/.test(e.message); }
    })(), 'e.g. $.att.expiry');
    ok('canonical() still encodes every JSON value it should',
      C.canonical({ b: true, s: 'x', n: 1.5, z: null, a: [1, 'two', { q: false }], o: {} })
        === '{"a":[1,"two",{"q":false}],"b":true,"n":1.5,"o":{},"s":"x","z":null}');

    /* -------------------------------------------------------- commitment */
    group('Commitment (persistentCommit)');
    const doc = enc('RETAINER AGREEMENT \u2014 Doe v. Acme Holdings');
    const n1 = C.randomNonce(), n2 = C.randomNonce();
    const c1 = await C.commit(doc, n1);
    ok('commit is deterministic', C.hex(c1) === C.hex(await C.commit(doc, n1)));
    ok('commit is salted: same document, new nonce, new commitment',
      C.hex(c1) !== C.hex(await C.commit(doc, n2)));
    ok('commit is not a bare SHA-256 of the document',
      C.hex(c1) !== C.hex(await C.sha256(doc)));
    ok('holder of document + nonce can re-derive it', await C.verifyCommit(doc, n1, c1));
    ok('one flipped byte breaks it', !(await C.verifyCommit(enc('RETAINER AGREEMENT \u2014 Doe v. Acme Holdinqs'), n1, c1)));

    // C-02. The v1 construction was SHA-256(domain || nonce || content) over two
    // variable-length fields, so the party holding the nonce could open one commitment
    // to two documents by sliding the leading bytes of the document onto the nonce.
    // Everything below fails against v1 and passes against v2.
    ok('the commitment domain is versioned v2, so a v1 commitment can never be read as a v2 one',
      /:v2$/.test(C.COMMIT_DOMAIN), C.COMMIT_DOMAIN);
    const rejects = (n) => C.commit(doc, C.randomNonce(n)).then(() => false, () => true);
    ok('an 8-byte nonce is refused', await rejects(8));
    ok('a 16-byte nonce is refused (v1 accepted it: 16 was the lower bound C-02 walked through)',
      await rejects(16));
    ok('a 31-byte nonce is refused', await rejects(31));
    ok('a 33-byte nonce is refused: the field is exactly 32, not at least 32', await rejects(33));
    ok('exactly 32 bytes is accepted', await C.commit(doc, C.randomNonce(32)).then(() => true, () => false));
    const pre = enc('VOID \u2014 DO NOT FILE. '), body = enc('Settlement offer: $100,000.');
    const whole = await C.commit(C.concat(pre, body), n1);
    const equivocated = await C.commit(body, C.concat(n1, pre))
      .then((h) => C.hex(h) === C.hex(whole), () => false);
    ok('one commitment cannot open to two documents: moving a leading caption onto the nonce is refused',
      equivocated === false, 'commit(prefix||body, N) !== commit(body, N||prefix)');
    ok('dropping the caption does not re-derive the commitment either',
      !(await C.verifyCommit(body, n1, whole)));

    /* ------------------------------------------------------------ merkle */
    group('Merkle tree');
    const proofHex = (p) => p.map((s) => s.side + ':' + C.hex(s.hash)).join('|');
    for (const N of [1, 2, 3, 5, 8, 17]) {
      const leaves = [];
      for (let i = 0; i < N; i++) leaves.push(await C.commit(enc('doc ' + i), C.randomNonce(32)));
      const rootHash = await C.merkleRoot(leaves);
      // APPSEC-02: one pass for every proof, instead of rebuilding the tree per leaf.
      const batch = await C.merkleProofs(leaves);
      let allGood = true, forgeryRejected = true, batchMatches = batch.length === N;
      for (let i = 0; i < N; i++) {
        const proof = await C.merkleProof(leaves, i);
        if (!(await C.verifyProof(leaves[i], proof, rootHash))) allGood = false;
        if (proofHex(batch[i]) !== proofHex(proof)) batchMatches = false;
        if (N > 1 && await C.verifyProof(leaves[(i + 1) % N], proof, rootHash)) forgeryRejected = false;
      }
      ok(`N=${N}: every leaf proves into the root`, allGood);
      ok(`N=${N}: merkleProofs(leaves)[i] is identical to merkleProof(leaves, i) for every i`, batchMatches);
      // N=1 has no other leaf, so asserting this there would assert nothing.
      if (N > 1) ok(`N=${N}: a different leaf never proves into it`, forgeryRejected);
    }
    // C-06 / A-4. A raw proof over n leaves is n-shaped: its length bounds the batch size.
    // That is a fact about this primitive, not a bug in it — certificate.js has four fixed
    // claims and nothing to hide. It is the reason protocol.js pads to a fixed depth before
    // it hands a proof to anyone.
    const depthOf = async (n) => {
      const ls = [];
      for (let i = 0; i < n; i++) ls.push(await C.sha256('leaf ' + i));
      return (await C.merkleProof(ls, 0)).length;
    };
    const d3 = await depthOf(3), d512 = await depthOf(512);
    ok('a raw proof length tracks the tree, which is why the Protocol pads before disclosing one',
      d3 !== d512, `n=3 -> ${d3} steps, n=512 -> ${d512} steps`);
    const two = [await C.sha256('a'), await C.sha256('b')];
    ok('order matters (left/right are not interchangeable)',
      C.hex(await C.merkleRoot(two)) !== C.hex(await C.merkleRoot([two[1], two[0]])));

    /* ------------------------------------------------------------- ECDSA */
    group('ECDSA P-256 signing');
    const keys = await C.generateSigningKey();
    const payload = { statement: 'signed', n: 7, nested: { z: [1, 2] } };
    const sig = await C.signJSON(keys.privateKey, payload);
    ok('sign then verify', await C.verifyJSON(keys.publicKey, sig, payload));
    ok('a changed field fails', !(await C.verifyJSON(keys.publicKey, sig, { ...payload, n: 8 })));
    const pubB64 = await C.exportPublicKey(keys.publicKey);
    ok('exported public key verifies the same signature',
      await C.verifyJSON(await C.importPublicKey(pubB64), sig, payload));
    ok('someone else\u2019s key does not verify',
      !(await C.verifyJSON((await C.generateSigningKey()).publicKey, sig, payload)));
    report('key fingerprint', null, await C.keyFingerprint(pubB64));

    /* -------------------------------------------- point compression + seal */
    group('Sealed attestation (ECDH P-256 + AES-GCM)');
    let compOK = true;
    for (let i = 0; i < 5; i++) {
      const k = await C.generateReaderKey();
      const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', k.publicKey));
      if (C.hex(C.decompressPoint(C.compressPoint(raw))) !== C.hex(raw)) compOK = false;
    }
    ok('P-256 point compression round-trips (65 bytes \u2194 33)', compOK);
    const reader = await C.generateReaderKey();
    const code = await C.readerCode(reader.publicKey);
    report('reader code', null, code + '  (' + code.replace(/-/g, '').length + ' characters)');
    const sealed = await C.seal(enc('for the court only'), await C.importReaderCode(code));
    ok('reader opens what was sealed to their code',
      dec(await C.unseal(sealed, reader.privateKey)) === 'for the court only');
    ok('a different reader cannot open it',
      await C.unseal(sealed, (await C.generateReaderKey()).privateKey).then(() => false, () => true));
    const tampered = { ...sealed, ct: C.b64url((() => { const b = C.unb64url(sealed.ct); b[0] ^= 1; return b; })()) };
    ok('a tampered ciphertext is rejected by AES-GCM',
      await C.unseal(tampered, reader.privateKey).then(() => false, () => true));
    ok('the code survives being read aloud (case and spacing)',
      dec(await C.unseal(await C.seal(enc('x'), await C.importReaderCode(code.toLowerCase().replace(/-/g, ' '))), reader.privateKey)) === 'x');

    // C-12. The code used to be 53 characters with no check character, and its last
    // character was malleable: two codes decoded to the same key. Now it is 53 + 1.
    const flat = code.replace(/-/g, '');
    ok('the reader code carries a check character (53 + 1 = 54)',
      flat.length === C.READER_CODE_CHARS && flat.length === 54, flat.length + ' characters');
    ok('the check character is the one the code claims',
      C.checkSymbol(C.unbase32(flat.slice(0, -1))) === flat.slice(-1));
    let slipsCaught = 0, slipsTried = 0;
    for (const at of [0, 7, 26, 51, 52, 53]) {
      for (const ch of '0123456789ABCDEFGHJKMNPQRSTVWXYZ') {
        if (ch === flat[at]) continue;
        slipsTried++;
        const bad = flat.slice(0, at) + ch + flat.slice(at + 1);
        if (await C.importReaderCode(bad).then(() => false, () => true)) slipsCaught++;
      }
    }
    ok('every single mistyped character is caught, including in the check character itself',
      slipsCaught === slipsTried, slipsCaught + '/' + slipsTried + ' rejected');
    ok('a dropped character is caught on length, before any point decoding',
      await C.importReaderCode(flat.slice(0, -1)).then(() => false, () => true));
    ok('the last character is no longer malleable: the spare bit must be zero',
      (() => {
        const body = flat.slice(0, -1), last = body[body.length - 1];
        const twin = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'['0123456789ABCDEFGHJKMNPQRSTVWXYZ'.indexOf(last) ^ 1];
        try { C.unbase32(body.slice(0, -1) + twin); return false; } catch { return true; }
      })(), 'two codes can no longer decode to one key');

    /* --------------------------------------------------------- notarize */
    if (B.notarize) {
      group('Notarize');
      const nonce = C.randomNonce(32);
      const rec = await B.notarize.notarizeBytes(enc('exhibit A'), nonce, 'filed');
      ok('record carries a commitment, not the document digest', rec.commitment !== rec.digest);
      ok('the commitment re-derives from the file plus the nonce',
        await C.verifyCommit(enc('exhibit A'), nonce, C.unhex(rec.commitment)));
      ok('a notarization with a short nonce is refused, not quietly published',
        await B.notarize.notarizeBytes(enc('exhibit A'), C.randomNonce(16), 'filed')
          .then(() => false, () => true));
      ok('checking a commitment with a wrong-length nonce is a false verdict, not an exception',
        (await C.verifyCommit(enc('exhibit A'), C.randomNonce(16), C.unhex(rec.commitment))) === false);
    }


    /* ------------------------------------------------- x402, actually settled */
    // The 402 used to be the end of the road: the server quoted a price and nothing on
    // either side could act on it. RECORDED_402 below is a REAL answer this backend gave
    // on 2026-09-23 to a licence with no balance left. Nothing here touches the network:
    // the call takes its `fetch` as an argument so a stub can stand in for one.
    //
    // The thing this section exists to hold still is that the page shows terms a human
    // can PAY — the whole address, the exact amount, each with its own copy button — and
    // that it is not, and does not pretend to be, a wallet.
    if (B.notarize && B.notarize.payTerms) {
      group('Settlement (x402)');
      const N = B.notarize;
      const RECORDED_402 = {
        "error": "payment_required",
        "message": "This call costs $0.01 and the licence's prepaid balance is $0.00. Top it up with the payment below and retry this request with the payment header: the whole amount is added to the balance and this call is taken off it. Or ask for Stripe billing, which invoices at month end.",
        "price": {"usd": "0.01", "cents": 1, "balanceUsd": "0.00"},
        "x402Version": 1,
        "accepts": [
          {
            "scheme": "exact",
            "network": "cardano-preprod",
            "asset": "lovelace",
            "amount": "10.00",
            "maxAmountRequired": "10000000",
            "payTo": "addr_test1qptn0hsk2z8wpygayemqetnt0lh694e60p0htrtj0z25fvces7r4ar3usmzmtxp2vpnj62ytuej023a7n60kfan6q0fqpm90vk",
            "resource": "http://127.0.0.1:8402/v1/notarize",
            "description": "Top up the prepaid balance; this call costs $0.01",
            "mimeType": "application/json",
            "maxTimeoutSeconds": 300,
            "extra": {
              "name": "tADA",
              "decimals": 6,
              "unit": "top-up",
              "amountDisplay": "10.000000 tADA"
            }
          }
        ],
        "settlement": {
          "status": "live",
          "detail": "Send exactly 10.000000 tADA (10000000 lovelace) to addr_test1qptn0hsk2z8wpygayemqetnt0lh694e60p0htrtj0z25fvces7r4ar3usmzmtxp2vpnj62ytuej023a7n60kfan6q0fqpm90vk, wait for it to be in a block, then retry this same request with the header `X-PAYMENT: <transaction hash>`. The server reads that transaction off cardano-preprod through Blockfrost and sums only the outputs that go to the address above in the quoted asset. One transaction is one top-up, ever.",
          "header": "X-PAYMENT: <64-hex transaction hash>",
          "payTo": "addr_test1qptn0hsk2z8wpygayemqetnt0lh694e60p0htrtj0z25fvces7r4ar3usmzmtxp2vpnj62ytuej023a7n60kfan6q0fqpm90vk",
          "network": "cardano-preprod",
          "asset": "lovelace",
          "assetName": "tADA",
          "amountBaseUnits": 10000000,
          "amountDisplay": "10.000000 tADA",
          "minConfirmations": 1,
          "maxAgeSeconds": 86400,
          "receipt": "GET /v1/payments/{txHash} — free, no key, like verification",
          "notWallet": "This server never holds a key for that address and never signs anything: it only ever reads. Sign the payment in your own wallet."
        }
      };
      const TREASURY = RECORDED_402.accepts[0].payTo;
      const t = N.payTerms(RECORDED_402);

      ok('the terms come out of the server\u2019s own 402: address, amount and network',
        t.payTo === TREASURY && t.amountBaseUnits === 10000000
          && t.network === 'cardano-preprod', t.network);
      ok('preprod is quoted in tADA, the asset that exists there, and never in USDM',
        t.asset === 'lovelace' && t.assetName === 'tADA'
          && JSON.stringify(RECORDED_402).indexOf('USDM') < 0);
      ok('base units are turned into the string a wallet is typed with',
        N.baseUnits(10000000, 6) === '10.000000' && N.baseUnits(1, 6) === '0.000001'
          && N.baseUnits(0, 6) === '0.000000' && N.baseUnits(999, 6) === '0.000999',
        N.baseUnits(10000000, 6) + ' tADA');

      const panel = N.payTermsHTML(t);
      ok('the address is shown in full, not shortened \u2014 an elided address cannot be checked',
        panel.indexOf(TREASURY) >= 0 && panel.indexOf('\u2026') < 0);
      ok('the address has a copy button carrying the exact address',
        new RegExp('data-copy="' + TREASURY + '"\\s*>Copy address').test(panel));
      ok('the amount has its own copy button, and it copies the number, not a sentence',
        /data-copy="10\.000000"\s*>Copy amount/.test(panel));
      ok('there is a box for the transaction hash and a button to retry with it',
        /id="nt-tx"/.test(panel) && /id="nt-retry"/.test(panel)
          && panel.indexOf('X-PAYMENT') >= 0);
      ok('it says the payment must be IN A BLOCK, because a submitted hash is not payment',
        panel.indexOf('in a block') >= 0 && panel.indexOf('not payment yet') >= 0);
      ok('it says plainly that this page holds no key and signs nothing',
        /holds no key, signs\s+nothing/.test(panel) && /never asks your wallet/.test(panel));
      ok('and it says the same transaction cannot be spent twice',
        panel.indexOf('exactly one charge') >= 0);

      // Not a wallet, and not by politeness: there is no wallet API called anywhere in
      // this module. A demo that quietly grew a CIP-30 connect button would be asking
      // readers to expose a real wallet to a demo page.
      if (typeof require === 'function' && typeof process !== 'undefined') {
        const src = require('fs').readFileSync(require('path').join(__dirname, 'notarize.js'), 'utf8');
        // The prose says "no CIP-30" out loud, so the scan looks for the API rather
        // than for the phrase: what must be absent is the call, not the word.
        ok('notarize.js calls no wallet API at all: no CIP-30, no enable(), no signTx',
          !/window\.cardano|cardano\.\w+\.enable|\.enable\(\)|signTx\(|signData\(/i.test(src)
            && src.indexOf('THIS IS NOT A WALLET') >= 0);
        ok('and it never asks for a private key or a seed phrase',
          !/privateKey|mnemonic|seed ?phrase|skey/i.test(src));
      } else {
        report('notarize.js calls no wallet API at all', null,
          'SKIPPED \u2014 no filesystem in the browser run');
        report('and it never asks for a private key or a seed phrase', null, '');
      }

      // What settled. Specific, and checkable by anyone: the receipt endpoint is free.
      const SETTLED = {
        status: 'settled',
        txHash: 'c3a4f1b2e5d6079a8b4c2d1e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a',
        network: 'cardano-preprod', asset: 'lovelace', assetName: 'tADA',
        payTo: TREASURY, amount: '10.000000 tADA', amountBaseUnits: 10000000,
        requiredBaseUnits: 10000000, confirmations: 4, spendableAgain: false,
      };
      const done = N.settledHTML(SETTLED, 'http://127.0.0.1:8402');
      ok('a settlement says what settled: the amount, the address and the transaction',
        done.indexOf('10.000000 tADA') >= 0 && done.indexOf(TREASURY) >= 0
          && done.indexOf(SETTLED.txHash) >= 0 && /4\s+confirmations/.test(done));
      ok('it points at the free receipt, so a reader can check it without a key',
        done.indexOf('/v1/payments/' + SETTLED.txHash) >= 0 && done.indexOf('needs no key') >= 0);
      ok('a notarisation taken off prepaid credit is not reported as settled on chain',
        N.settledHTML({ status: 'credit', detail: 'Taken off prepaid filings.' }) === '');

      // A refusal repeats the server's own words. An underpayment, a replay and a
      // Blockfrost outage are three different problems, and a reader told "payment
      // failed" would treat them the same.
      const replay = N.payRefusedHTML({ error: 'payment_replayed',
        message: 'That transaction has already settled a charge on this appliance.' }, 409);
      ok('a refused payment repeats the server\u2019s reason and its status code',
        replay.indexOf('already settled a charge') >= 0 && replay.indexOf('409') >= 0
          && replay.indexOf('payment_replayed') >= 0);
      ok('and it says nothing was recorded and nothing was charged',
        replay.indexOf('Nothing was recorded and nothing was charged') >= 0);

      // The call. A stub fetch, so this runs with no appliance and no network.
      const seen = {};
      const stub = (status, body) => (url, init) => {
        seen.url = url; seen.init = init;
        return Promise.resolve({ status: status, json: () => Promise.resolve(body) });
      };

      const first = await N.runNotarize({ base: 'http://127.0.0.1:8402/', key: 'blf_lk_a_key',
        digest: 'b'.repeat(64), disposition: 'filed', nonce: 'a'.repeat(64),
        fetch: stub(402, RECORDED_402) });
      ok('the first attempt posts to /v1/notarize on the named appliance, with no payment',
        seen.url === 'http://127.0.0.1:8402/v1/notarize'
          && seen.init.headers.Authorization === 'Bearer blf_lk_a_key'
          && !('X-PAYMENT' in seen.init.headers) && first.status === 402);
      ok('the document digest is what is sent \u2014 never the file, which this page never had',
        JSON.parse(seen.init.body).documentDigest === 'b'.repeat(64)
          && seen.init.body.indexOf('content') < 0);

      const retry = await N.runNotarize({ base: 'http://127.0.0.1:8402', key: 'blf_lk_a_key',
        digest: 'b'.repeat(64), payment: '  ' + SETTLED.txHash.toUpperCase() + '  ',
        fetch: stub(200, { record: { id: 1 }, settlement: SETTLED }) });
      ok('the retry carries the hash as X-PAYMENT, trimmed and lower-cased for the server',
        seen.init.headers['X-PAYMENT'] === SETTLED.txHash && retry.status === 200
          && retry.body.settlement.status === 'settled');
      ok('an empty hash never becomes an X-PAYMENT header: a blank is not an attempt to pay',
        await N.runNotarize({ payment: '   ', digest: 'b'.repeat(64), fetch: stub(402, RECORDED_402) })
          .then(() => !('X-PAYMENT' in seen.init.headers)));
      ok('an appliance that does not answer is an answer, not an exception',
        await N.runNotarize({ base: 'http://127.0.0.1:9', digest: 'b'.repeat(64),
          fetch: () => Promise.reject(new Error('connection refused')) })
          .then((r) => r.status === 0 && r.body.error === 'unreachable'));
    }

    /* ------------------------------------------------------ demo inputs */
    // No demo field arrives with invented text sitting in it as if the reader typed it:
    // it is a dropdown, it ends with "Write my own", and the free-text box starts empty.
    if (B.ui && B.ui.wmField) {
      group('Demo inputs');
      const U = B.ui;
      const models = (B.certificate && B.certificate.CERT_OPTIONS.model) || [];
      const html = U.wmField({ id: 'demo-model', label: 'Model', options: models });
    ok('a demo field renders one plain box carrying the default answer',
      /<input[^>]*class="wm-input wm-box"/.test(html) && !/<select/.test(html)
      && html.indexOf('value="' + (models[0] || '') + '"') >= 0);
    ok('no dropdown and no "Write my own" control survives in a field',
      html.indexOf('data-wm-select') < 0 && html.indexOf('data-wm-own') < 0
      && html.indexOf('<datalist') < 0);
      ok('the model list offers Astra 6 and Opus 5.1, neither of which exists',
        models.indexOf('Astra 6') >= 0 && models.indexOf('Opus 5.1') >= 0, models.join(' \u00b7 '));

      // wmValue() is the whole contract between the widgets and the crypto: the chosen
      // option, or whatever was typed. Stubbed rather than rendered, because this suite
      // runs under node with no DOM.
      const stub = (selected, typed) => {
        const field = {
          querySelector: (s) => (s === '.wm-select' ? { value: selected }
            : s === '.wm-input' ? { value: typed } : null),
        };
        return { querySelector: (s) => (s.indexOf('[data-wm=') === 0 ? field : null) };
      };
      ok('choosing "Write my own" makes the typed text the value of the field',
        U.wmValue(stub(U.WM_OWN, 'Astra 6'), 'demo-model') === 'Astra 6');
      ok('choosing a listed option ignores anything left in the box',
        U.wmValue(stub('Opus 5.1', 'stale text'), 'demo-model') === 'Opus 5.1');
    }

    /* ------------------------------------------------------ certificate */
    if (B.certificate) {
      group('Certificate');
      const K = B.certificate;
      const fields = JSON.parse(JSON.stringify(K.CERT_DEFAULTS));
      fields.documentDigest = C.hex(await C.sha256('the filing'));
      // The case number is the reader's to type now, so the fixture types one.
      fields.caseNumber = '3:26-cv-99999';
      fields.licenseExpires = new Date(Date.now() + 45 * 864e5).toISOString();
      // The version is the reader's to type now, so the fixture types one.
      fields.evidence['model-manifest'].version = 'q5_K_M / 2026.07';
      fields.evidence['model-manifest'].manifestDigest = C.hex(await C.sha256('manifest'));
      fields.evidence['attorney-adoption'].sendRecordDigest = C.hex(await C.sha256('send'));
      fields.evidence['attorney-adoption'].adoptedAt = new Date().toISOString();
      fields.evidence['citations-verified'].retrievalLogDigest = C.hex(await C.sha256('log'));
      const cert = await K.buildCertificate(fields);
      // A registered demo key once the trust root lands (APPSEC-01 / C-01); until then a
      // fresh key, which is what the old self-certifying verifier accepted.
      const certKeys = K.demoSigningKeys ? await K.demoSigningKeys() : await C.generateSigningKey();
      const signedCert = await K.signCertificate(cert, certKeys);
      const v = await K.verifyCertificate(signedCert);
      ok('a well-formed certificate signed by a registered key verifies', v.ok, v.status || '');
      // C-01 / C-17: the suite used to assert nothing about WHOSE key signed. Skipped, not
      // deleted, while the pinned trust root is still landing in certificate.js.
      if (K.demoSigningKeys) {
        const stranger = await K.signCertificate(cert, await C.generateSigningKey());
        ok('an unregistered key is not a pass',
          (await K.verifyCertificate(stranger)).status === 'unregistered');
      } else {
        report('an unregistered key is not a pass', null,
          'SKIPPED \u2014 waiting on certificate.demoSigningKeys() and the pinned trust root');
      }
      ok('all four claims are present and proved',
        v.claims.length === 4 && v.claims.every((c) => c.ok), v.claims.map((c) => c.id).join(', '));
      ok('every claim proves into the claims root', v.claims.every((c) => c.included));
      const url = K.certificateURL(signedCert);
      ok('the verification URL round-trips through base64',
        (await K.verifyCertificate(K.decodePayload(url))).ok, url.slice(0, 28) + '\u2026 (' + url.length + ' chars)');
      const edited = JSON.parse(JSON.stringify(signedCert));
      edited.cert.claims[1].evidence.attorney = 'Someone Else, Esq.';
      const ve = await K.verifyCertificate(edited);
      ok('editing a claim after signing breaks the signature', !ve.signature);
      ok('editing a claim also breaks the claims root', !ve.rootOK);
      const gap = JSON.parse(JSON.stringify(signedCert));
      gap.cert.claims[2].evidence.verified = 9;
      const vg = await K.verifyCertificate(gap);
      ok('partly verified citations are reported, not passed',
        vg.claims[2].ok === false && /unverified/.test(vg.claims[2].missing.join(' ')));
      const leak = JSON.parse(JSON.stringify(signedCert));
      leak.cert.claims[3].evidence.identifiersReachedModel = 1;
      ok('an identifier reaching a model fails claim 4',
        (await K.verifyCertificate(leak)).claims[3].ok === false);
    }

    /* --------------------------------------------- certificate form (demo) */
    // The form Kevin looks at. Three things are asserted here that nothing else covers:
    // "Write my own" lives INSIDE the dropdown, every dropdown offers N/A, and a value
    // typed through "Write my own" reaches the SIGNED payload unchanged. The last one is
    // the silent breakage: the page would still look right while signing the wrong text.
    if (B.certificate && B.certificate.certFormHTML) {
      group('Certificate form');
      const K = B.certificate;
      const U = B.ui;
      const form = K.certFormHTML(K.CERT_DEFAULTS);

      // --- one control per answer -----------------------------------------
      // One control per answer: a text box with a <datalist> behind it. Picking a listed
      // answer and typing your own happen in the SAME box, so there is no second box to
      // get out of step with what gets signed.
      const boxes = form.match(/<input[^>]*class="wm-input wm-box"[^>]*>/g) || [];
      ok('every answer in the certificate form is one plain box the reader types in',
        boxes.length > 0 && !/<select\b/.test(form) && form.indexOf('<datalist') < 0,
        boxes.length + ' boxes');
      ok('no free-standing "Write my own" button survives anywhere in the form',
        form.indexOf('data-wm-own') < 0 && !/>\s*Write my own\s*<\/button>/.test(form));
      ok('N/A is not a menu entry any more: a blank box is recorded as N/A at signing',
        K.BLANKABLE.length > 0 && (await K.certFieldsFrom(() => '')).caseNumber === K.NA);
      ok('no second box is created for typing: there is no hidden free-text twin',
        form.indexOf('data-wm-select') < 0 && form.indexOf('data-wm-own') < 0
          && !/<select\b/.test(form));

      // --- the fields that are no longer dropdowns ------------------------
      const control = (id) => {
        const m = new RegExp('<(input|select|output)\\b[^>]*\\bid="' + id + '"[^>]*>').exec(form);
        return m ? m[0] : '';
      };
      ok('case number is a plain box carrying the demo default, typed over in one box',
        /^<input/.test(control('ct-case'))
          && control('ct-case').indexOf('value="Case - 123456"') >= 0
          && control('ct-case').indexOf('placeholder="Type your own\u2026"') >= 0);
      ok('the firm is fixed at Bailment Law and is not a control at all',
        K.DEMO_FIRM === 'Bailment Law' && control('ct-firm-fixed').indexOf('<output') === 0
          && form.indexOf('data-wm="ct-firm"') < 0, K.DEMO_FIRM);
      for (const [id, label] of [['ct-atty', 'attorney'], ['ct-bar', 'bar number']]) {
        ok('claim 2: ' + label + ' is a typed box whose example is a placeholder, not a value',
          /^<input/.test(control(id)) && /placeholder="[^"]+"/.test(control(id))
            && control(id).indexOf('value=') < 0 && form.indexOf('data-wm="' + id + '"') < 0);
      }
      ok('claim 2 has no "Write my own" anywhere: attorney, bar number and court are typed in',
        form.indexOf('data-wm="ct-atty"') < 0 && form.indexOf('data-wm="ct-bar"') < 0
          && form.indexOf('data-wm="ct-court-specific"') < 0);
      ok('jurisdiction is a state dropdown with an always-visible optional court box underneath',
        form.indexOf('data-wm="ct-juris"') >= 0 && K.CERT_OPTIONS.jurisdiction.length >= 50
          && /^<input/.test(control('ct-court-specific'))
          && control('ct-court-specific').indexOf('style="display:none"') < 0);
      ok('the redactor version defaults to bailee-redactor 4.2.1 in a box you can retype',
        K.CERT_DEFAULTS.evidence['no-identifier'].redactorVersion === 'bailee-redactor 4.2.1 (signed)'
          && form.indexOf('value="bailee-redactor 4.2.1 (signed)"') >= 0);

      // --- claim 1: version is filled in FROM the model, and still shipped --
      ok('the model list offers In House Model as well as Astra 6 and Opus 5.1',
        ['In House Model', 'Astra 6', 'Opus 5.1'].every((m) => K.CERT_OPTIONS.model.indexOf(m) >= 0),
        K.CERT_OPTIONS.model.join(' \u00b7 '));
    ok('the version is never filled in for the reader: every model leaves it empty',
      ['Llama 3.3 70B Instruct', 'Qwen 2.5 72B', 'Astra 6', 'In House Model', 'Nobody Listed']
        .every((m) => K.modelVersion(m) === ''));
      ok('the version box is editable, visible, and carries the demo default',
        /^<input/.test(control('ct-modelver'))
          && control('ct-modelver').indexOf('value="Version 1234"') >= 0
          && control('ct-modelver').indexOf('readonly') < 0);
      ok('provider is optional and can be N/A',
        (await K.certFieldsFrom(() => '')).evidence['model-manifest'].provider === K.NA);

      // --- the thing most likely to break silently ------------------------
      // Free text, chosen through "Write my own", all the way to a signature. wmValue()
      // is driven the way the page drives it: select on "Write my own", text in the box.
      const stub = (selected, typed) => {
        const field = {
          querySelector: (s) => (s === '.wm-select' ? { value: selected }
            : s === '.wm-input' ? { value: typed } : null),
        };
        return { querySelector: (s) => (s.indexOf('[data-wm=') === 0 ? field : null) };
      };
      const TYPED = {
        model: 'Hand-rolled Mixtral, 2026-09 snapshot',
        provider: 'A provider nobody put in the list',
        redactorVersion: 'my-own-redactor 0.0.1',
        pipelineStep: 'my-own-cite-check@0.1',
        court: 'Court of the Reader\u2019s Own Invention',
      };
      const own = {};
      for (const k of Object.keys(TYPED)) own[k] = U.wmValue(stub(U.WM_OWN, TYPED[k]), 'ct-x');
      ok('"Write my own" text comes back out of the field exactly as typed',
        Object.keys(TYPED).every((k) => own[k] === TYPED[k]));

      const typedFields = await K.certFieldsFrom((name) => (
        name in TYPED ? own[name]
          : name === 'version' ? 'my own build / 9.9'
            : name === 'caseNumber' ? '3:26-cv-99999'
              : name === 'attorney' ? 'Ada Lovelace, Esq.'
                : name === 'barNumber' ? 'WSBA 00001'
                  : name === 'jurisdiction' ? 'Oregon'
                    : name === 'specificCourt' ? 'Multnomah County Circuit Court'
                      : ''));
      const typedSigned = await K.signCertificate(
        await K.buildCertificate(typedFields), await K.demoSigningKeys());
      const tv = await K.verifyCertificate(typedSigned);
      const ev = (id) => typedSigned.cert.claims.find((c) => c.id === id).evidence;
      ok('a certificate built entirely from "Write my own" text still verifies', tv.ok, tv.status);
      ok('the typed model survives into the SIGNED payload, byte for byte',
        ev('model-manifest').model === TYPED.model, ev('model-manifest').model);
      ok('the typed provider, redactor and pipeline step survive into the SIGNED payload',
        ev('model-manifest').provider === TYPED.provider
          && ev('no-identifier').redactorVersion === TYPED.redactorVersion
          && ev('citations-verified').pipelineStep === TYPED.pipelineStep);
      ok('the typed court survives into the SIGNED payload',
        typedSigned.cert.filing.court === TYPED.court);
      ok('removing the version from nobody\u2019s form did not remove it from the wire: '
        + 'every CLAIM_SPEC field is still present',
        K.CLAIM_SPEC.every((s) => s.required.every((k) => {
          const v = ev(s.id)[k];
          return v !== undefined && v !== null && v !== '';
        })), 'version=' + ev('model-manifest').version);
      ok('a state plus a specific court are both recorded in the jurisdiction',
        ev('attorney-adoption').jurisdiction === 'Oregon \u2014 Multnomah County Circuit Court',
        ev('attorney-adoption').jurisdiction);
      ok('the firm on the wire is the licensed firm, not anything the reader could pick',
        typedSigned.cert.license.firm === K.DEMO_FIRM);
      const blank = await K.certFieldsFrom(() => '');
      const blankSigned = await K.signCertificate(await K.buildCertificate(blank), await K.demoSigningKeys());
      ok('an untouched form still signs a complete certificate: no field is left as a hole',
        (await K.verifyCertificate(blankSigned)).ok);
      ok('a cleared version box records N/A rather than an empty claim',
        blank.evidence['model-manifest'].version === K.NA);

      /* ------------------- blank means N/A, and the reader is warned by name first */
      // Kevin, verbatim: "Sign with N/A on any missing fields but always warn before
      // submitting that fields have been left blank." Both halves, in that order. The
      // first half is the one that regresses silently: the page looks identical while
      // it signs a placeholder lawyer onto a court document.
      const evb = (id) => blankSigned.cert.claims.find((c) => c.id === id).evidence;
      ok('claim 2 left blank is signed as N/A, for the attorney and for the bar number',
        evb('attorney-adoption').attorney === K.NA && evb('attorney-adoption').barNumber === K.NA,
        evb('attorney-adoption').attorney + ' / ' + evb('attorney-adoption').barNumber);
      ok('a blank case number is signed as N/A',
        blankSigned.cert.filing.caseNumber === K.NA, blankSigned.cert.filing.caseNumber);
      ok('a blank specific court is recorded as N/A beside the state, not silently dropped',
        (await K.certFieldsFrom((n) => (n === 'jurisdiction' ? 'Oregon' : '')))
          .evidence['attorney-adoption'].jurisdiction === 'Oregon \u2014 ' + K.NA);
      ok('neither one stated reads as a single N/A, so the certificate marks it as not stated',
        blank.evidence['attorney-adoption'].jurisdiction === K.NA
          && K.certNAFields(blankSigned.cert).indexOf('jurisdiction') >= 0);
      // The whole point. A placeholder is a hint; signing it is signing somebody else's
      // example. Checked against the payload as it travels, not just as it is built.
      const onTheWire = JSON.stringify(K.decodePayload(K.certificateURL(blankSigned)));
      ok('not one of the greyed-out examples appears anywhere in the SIGNED payload',
        Object.values(K.EXAMPLES).every((ex) => onTheWire.indexOf(ex) < 0),
        Object.values(K.EXAMPLES).join(' \u00b7 ') + ' \u2014 none present');
      ok('the examples that remain are shown only as placeholders, never as values',
        Object.values(K.EXAMPLES).filter((ex) => form.indexOf(ex) >= 0)
          .every((ex) => form.indexOf('placeholder="' + ex + '"') >= 0));
      ok('issuing anyway, with blanks, still produces a certificate the verifier accepts',
        (await K.verifyCertificate(blankSigned)).status === 'verified');
      ok('every CLAIM_SPEC field of an untouched form is on the wire as a value, not a hole',
        K.CLAIM_SPEC.every((s) => s.required.every((k) => {
          const v = evb(s.id)[k];
          return v !== undefined && v !== null && v !== '';
        })));

      // --- the warning itself -------------------------------------------
      const someBlank = K.blankFields((n) =>
        (['attorney', 'barNumber', 'caseNumber'].indexOf(n) >= 0 ? '' : 'something'));
      ok('the warning lists precisely the blank fields, by the label the form shows',
        someBlank.map((b) => b.label).join(' | ') === 'Case number | Attorney | Bar number',
        someBlank.map((b) => b.label).join(' | '));
      ok('no blank fields means no warning at all \u2014 the happy path is still one click',
        K.blankFields(() => 'something').length === 0
          && K.blankWarningHTML(K.blankFields(() => 'something')) === '');
      ok('every field the warning can name is a control that actually exists in the form, '
        + 'so "go back" lands on it',
        K.BLANKABLE.every((f) => form.indexOf('id="' + f.id + '"') >= 0));
      ok('the labels the warning uses are the labels the form prints above the controls',
        K.BLANKABLE.every((f) => form.indexOf('>' + f.label + '</label>') >= 0));
      const wh = K.blankWarningHTML(someBlank);
      ok('the warning names the fields rather than saying "some fields are blank"',
        wh.indexOf('Case number, Attorney and Bar number will be recorded as N/A') >= 0
          && wh.indexOf('3 fields have been left blank') >= 0);
      ok('it says what each blank field will be recorded as, one line per field',
        (wh.match(/class="ct-warn-r">recorded as N\/A</g) || []).length === 3);
      ok('a blank that is NOT recorded as N/A says so in its own words',
        K.blankWarningHTML(K.blankFields((n) => (n === 'documentDigest' ? '' : 'x')))
          .indexOf('will be recorded as a stand-in digest computed from fixed demo text') >= 0);
      ok('the warning is an alertdialog, keyboard-focusable, tied to its own title and text',
        /role="alertdialog"/.test(wh) && /tabindex="-1"/.test(wh)
          && /aria-labelledby="ct-warn-t"/.test(wh) && /aria-describedby="ct-warn-d"/.test(wh)
          && /id="ct-warn-t"/.test(wh) && /id="ct-warn-d"/.test(wh));
      ok('two choices, both real buttons, both in plain words',
        /<button type="button" class="btn" id="ct-warn-back">Go back and fill them in<\/button>/.test(wh)
          && /<button type="button" class="btn ghost" id="ct-warn-go">Issue anyway, recording N\/A<\/button>/.test(wh));
      ok('the warning is rebuilt from the form every time: same blanks, same warning, '
        + 'and it has somewhere to appear',
        K.blankWarningHTML(someBlank) === wh && form.indexOf('id="ct-warn-slot"') >= 0);

      // --- N/A is visible on the certificate a court reads ---------------
      const blankDoc = K.certHTML(blankSigned.cert, 'verify.html#c=demo', 'ab:cd');
      ok('a field recorded as N/A reads as N/A on the issued certificate',
        blankDoc.indexOf('attorney=N/A') >= 0 && blankDoc.indexOf('>N/A<') >= 0);
      ok('and is marked so a court can tell it apart from a field somebody answered',
        (blankDoc.match(/class="cert-na"/g) || []).length >= 4);
      ok('the certificate says at the top which fields were not stated, rather than hiding it',
        blankDoc.indexOf('Not stated:') >= 0
          && K.certNAFields(blankSigned.cert).indexOf('attorney') >= 0
          && K.certNAFields(blankSigned.cert).indexOf('case number') >= 0,
        K.certNAFields(blankSigned.cert).join(', '));
      const answeredDigest = C.hex(await C.sha256('a filing somebody actually digested'));
      const fullCert = await K.buildCertificate(await K.certFieldsFrom((n) => (
        n === 'documentDigest' ? answeredDigest
          : n === 'citations' || n === 'verified' ? '7'
            : n === 'identifiersReachedModel' ? '0' : 'answered')));
      ok('a form with nothing left blank carries no N/A marks and no "not stated" banner',
        K.certNAFields(fullCert).length === 0
          && K.certHTML(fullCert, 'verify.html#c=demo', 'ab:cd').indexOf('cert-na') < 0);
      ok('and a fully answered form still verifies',
        (await K.verifyCertificate(await K.signCertificate(fullCert, await K.demoSigningKeys()))).ok);

      /* --------------------------------------------- the "?" explainers */
      // Every one of these was named as confusing. Each gets a "?" that opens on hover
      // AND on keyboard focus, with aria-describedby tying the two together.
      // The three computed digests left the form with the note that explained them, so
      // the list is the fields a reader still fills in.
      const NEEDS_HELP = ['identifiersReachedModel', 'version', 'pipelineStep',
        'documentDigest'];
      ok('every field Kevin named as confusing has a "?" explainer in the form',
        NEEDS_HELP.every((k) => form.indexOf('id="ct-help-' + k + '"') >= 0),
        NEEDS_HELP.join(', '));
      ok('each explainer says something in plain English rather than repeating the label',
        NEEDS_HELP.every((k) => typeof K.HELP[k] === 'string' && K.HELP[k].split(' ').length >= 20));
      const q = K.ctHelp('version');
      ok('the "?" is a real button, so a keyboard can reach it', /^<span class="wm-help"><button type="button"/.test(q));
      ok('aria-describedby points at the tooltip that carries the explanation',
        /aria-describedby="ct-help-version"/.test(q)
          && /<span class="wm-tip" role="tooltip" id="ct-help-version">/.test(q));
      ok('the tooltip is the "?" button\u2019s immediate next sibling, which is what the '
        + 'hover and focus rules select on',
        /<\/button><span class="wm-tip"/.test(q));
      // Node only: the reveal is done in CSS, so the CSS is where it has to be proved.
      let appcss = '';
      if (typeof require === 'function' && typeof __dirname === 'string') {
        try { appcss = ['app.css', '../style.css'].map((f) => require('fs').readFileSync(require('path').join(__dirname, f), 'utf8')).join('\n'); }
        catch { appcss = ''; }
      }
      if (appcss) {
        const rule = (needle) => {
          const i = appcss.indexOf(needle);
          if (i < 0) return null;
          const open = appcss.indexOf('{', i);
          const start = appcss.lastIndexOf('}', i) + 1;
          return { sel: appcss.slice(start, open), body: appcss.slice(open + 1, appcss.indexOf('}', open)) };
        };
        const reveal = rule('.wm-q:focus-visible + .wm-tip');
        ok('app.css opens the explainer on hover AND on keyboard focus',
          !!reveal && /display:\s*block/.test(reveal.body)
            && /\.wm-q:hover\s*\+\s*\.wm-tip/.test(reveal.sel)
            && /\.wm-q:focus\s*\+\s*\.wm-tip/.test(reveal.sel)
            && /\.wm-q:focus-visible\s*\+\s*\.wm-tip/.test(reveal.sel),
          reveal ? reveal.sel.trim().replace(/\s+/g, ' ') : 'rule not found');
        const tip = rule(':is(.widget,.pf-dialog) .wm-tip{');
        ok('the explainer is hidden until then, sits below the field, and cannot swallow a click',
          !!tip && /display:\s*none/.test(tip.body) && /top:\s*100%/.test(tip.body)
            && /pointer-events:\s*none/.test(tip.body) && /left:\s*0/.test(tip.body));
        ok('the explainer is not the smallest text on the page',
          !!tip && /font-size:\s*\.98rem/.test(tip.body));

        // The warning is a confirmation, not fine print: its own box, its own focus
        // ring, and body text no smaller than the hints beside the fields.
        const warnBox = rule('.widget .ct-warn{');
        const warnP = rule('.widget .ct-warn p{');
        ok('the blank-field warning is a box of its own, not a line of fine print',
          !!warnBox && /border:/.test(warnBox.body) && /padding:/.test(warnBox.body));
        ok('the warning is readable at the current type size',
          !!warnP && /font-size:\s*1\.02rem/.test(warnP.body), warnP ? warnP.body.trim() : '');
        ok('the warning shows where the keyboard is when it opens',
          !!rule('.widget .ct-warn:focus{'));
        const na = rule('.widget .cert-na{');
        ok('N/A on the certificate is marked in a way that survives printing in black ink',
          !!na && /border-bottom:\s*1px dotted currentColor/.test(na.body)
            && appcss.indexOf('.widget .cert .cert-na{border-bottom:1px dotted #000}') >= 0);
      }
      // No browser setting may suppress this warning, and nothing may remember that it
      // was dismissed: it is built in the widget, from the form, on every press.
      let certsrc = '';
      if (typeof require === 'function' && typeof __dirname === 'string') {
        try { certsrc = require('fs').readFileSync(require('path').join(__dirname, 'certificate.js'), 'utf8'); }
        catch { certsrc = ''; }
      }
      if (certsrc) {
        ok('the warning is the widget\u2019s own, with nothing a browser can suppress and no '
          + '"do not show this again" to remember',
          !/window\.confirm|\balert\(|localStorage|sessionStorage/.test(certsrc));
      } else {
        report('app.css opens the explainer on hover AND on keyboard focus', null,
          'SKIPPED \u2014 no filesystem in the browser run');
      }
    }


    /* ------------------------------------------- claim 3, actually checked */
    // The two counts under claim 3 used to be whatever somebody typed into the form.
    // They are now filled in by POST /v1/citations/check, which the appliance answers
    // from a real CourtListener lookup. Nothing here touches the network: RECORDED is a
    // real answer this backend returned on 2026-09-22, and the call itself takes its
    // `fetch` as an argument so a stub can stand in for one.
    //
    // 925 F.3d 1339 is Varghese v. China Southern Airlines. It does not exist. A model
    // invented it, a lawyer filed it in Mata v. Avianca, and he was sanctioned for it.
    // The one thing this feature must do is catch that citation, so that is asserted by
    // name rather than left to a count.
    if (B.certificate && B.certificate.runCitationCheck) {
      group('Citations, checked (claim 3)');
      const K = B.certificate;
      const RECORDED = {
        "checked": true,
        "source": "courtlistener/v4 citation-lookup",
        "checkedAt": "2026-09-22T16:20:44.000Z",
        "citations": [
          {
            "citation": "576 U.S. 644",
            "status": 200,
            "found": true,
            "verdict": "verified",
            "note": "",
            "clusters": [
              {
                "id": 2812209,
                "caseName": "Obergefell v. Hodges",
                "court": "",
                "dateFiled": "2015-06-26",
                "absolute_url": "/opinion/2812209/obergefell-v-hodges/"
              }
            ]
          },
          {
            "citation": "678 F. Supp. 3d 443",
            "status": 404,
            "found": false,
            "verdict": "not found",
            "note": "Citation not found: '678 F. Supp. 3d 443'",
            "clusters": []
          },
          {
            "citation": "925 F.3d 1339",
            "status": 404,
            "found": false,
            "verdict": "not found",
            "note": "Citation not found: '925 F.3d 1339'",
            "clusters": []
          }
        ],
        "total": 3,
        "verified": 1,
        "unverified": 2,
        "retrievalLogDigest": "31f65d32b38d5d590e8e4564bcd2cef6d69d999ab1a6eeaecd211a803d31c5f7"
      };
      const cited = (s) => RECORDED.citations.find((c) => c.citation === s);
      const VARGHESE = '925 F.3d 1339', OBERGEFELL = '576 U.S. 644';

      ok('the example passage in the form carries the fabricated Varghese citation',
        K.CITE_EXAMPLE.indexOf(VARGHESE) >= 0 && K.CITE_EXAMPLE.indexOf(OBERGEFELL) >= 0,
        VARGHESE + ' \u2014 Mata v. Avianca');
      ok('a real citation reads as verified and a fabricated one as not found',
        K.citeVerdict(cited(OBERGEFELL)).label === 'verified'
          && K.citeVerdict(cited(VARGHESE)).label === 'not found');

      const rows = RECORDED.citations.map(K.citeRowHTML).join('');
      ok('every citation gets its own row, with its verdict in its own column',
        (rows.match(/class="ct-cite-row/g) || []).length === 3
          && (rows.match(/class="ct-cite-verdict"/g) || []).length === 3);
      const varRow = K.citeRowHTML(cited(VARGHESE));
      ok('the fabricated citation is marked bad, reads "not found", and links to no case',
        varRow.indexOf('class="ct-cite-row bad"') >= 0
          && varRow.indexOf('>not found<') >= 0
          && varRow.indexOf('<a ') < 0
          && varRow.indexOf(VARGHESE) >= 0, VARGHESE);
      ok('a case that was found is named and linked back to CourtListener, so the '
        + 'reader can go and look at the same page we looked at',
        rows.indexOf('Obergefell v. Hodges') >= 0
          && rows.indexOf('href="https://www.courtlistener.com/opinion/2812209/') >= 0);

      const out = K.citeResultHTML(RECORDED);
      ok('the summary reports 1 of 3, not a round number',
        out.indexOf('1 of 3 resolved to a real case') >= 0 && out.indexOf('2 did not') >= 0);
      ok('it says plainly that claim 3 will fail on these numbers, rather than hiding it',
        out.indexOf('will fail claim 3') >= 0);
      ok('the retrieval-log digest is shown, because that is what claim 3 now carries',
        out.indexOf('Retrieval log digest') >= 0
          && out.indexOf(RECORDED.retrievalLogDigest.slice(0, 12)) >= 0);

      // The fail-closed half. An answer that did not happen must not print a count:
      // there is no number in it to misread, and the page must not invent one.
      const failed = { checked: false, error: 'citation_check_timeout',
        message: 'CourtListener did not answer within 30s. Nothing was checked, so '
          + 'nothing is reported as verified.' };
      const failedOut = K.citeResultHTML(failed);
      ok('a check that did not happen reads as "Not checked": no rows, no counts, no digest',
        failedOut.indexOf('Not checked.') >= 0
          && failedOut.indexOf('ct-cite-row') < 0
          && failedOut.indexOf('resolved to a real case') < 0
          && failedOut.indexOf('Retrieval log digest') < 0
          && !/\b\d+ of \d+\b/.test(failedOut));
      ok('it repeats the server\u2019s own reason rather than inventing one',
        failedOut.indexOf('nothing is reported as verified') >= 0);
      ok('and it says the counts are still the reader\u2019s own, and unchecked',
        failedOut.indexOf('still yours to type') >= 0
          && failedOut.indexOf('nothing here has been verified against anything') >= 0);

      // The call. A stub fetch, so this runs with no appliance and no network.
      const seen = {};
      const stubFetch = (url, init) => {
        seen.url = url; seen.init = init;
        return Promise.resolve({ status: 200, json: () => Promise.resolve(RECORDED) });
      };
      const got = await K.runCitationCheck({ base: 'http://127.0.0.1:8402/',
        key: 'blf_lk_a_licence_key', text: K.CITE_EXAMPLE, fetch: stubFetch });
      ok('the check posts the passage to /v1/citations/check on the appliance',
        seen.url === 'http://127.0.0.1:8402/v1/citations/check'
          && seen.init.method === 'POST'
          && JSON.parse(seen.init.body).text === K.CITE_EXAMPLE, seen.url);
      ok('the licence key travels as a Bearer header and nowhere else',
        seen.init.headers.Authorization === 'Bearer blf_lk_a_licence_key'
          && seen.init.body.indexOf('blf_lk_a_licence_key') < 0);
      ok('the page holds no CourtListener token of its own: the appliance holds it',
        JSON.stringify(K).indexOf('Token ') < 0 && got.total === 3 && got.verified === 1);

      const down = await K.runCitationCheck({ text: 'x',
        fetch: () => Promise.reject(new Error('connection refused')) });
      ok('an appliance that is not running fails closed: checked=false and no counts',
        down.checked === false && down.total === undefined && down.verified === undefined,
        down.error);
      const unlicensed = await K.runCitationCheck({ text: 'x', fetch: () =>
        Promise.resolve({ status: 401, json: () => Promise.resolve(
          { error: 'no_licence', message: 'This endpoint issues signed certificates\u2026' }) }) });
      ok('a 401 is passed through in the server\u2019s own words, still checked=false',
        unlicensed.checked === false && unlicensed.error === 'no_licence'
          && K.citeResultHTML(unlicensed).indexOf('signed certificates') >= 0);

      // What gets SIGNED. This is the half that would break silently: the page could
      // show a perfect verdict list and still sign the demo's stand-in digest.
      const checkedFields = await K.certFieldsFrom((n) => (
        n === 'citations' ? String(RECORDED.total)
          : n === 'verified' ? String(RECORDED.verified)
            : n === 'retrievalLogDigest' ? RECORDED.retrievalLogDigest : ''));
      const ev3 = checkedFields.evidence['citations-verified'];
      ok('the digest of the real retrieval log reaches the signed certificate',
        ev3.retrievalLogDigest === RECORDED.retrievalLogDigest, ev3.retrievalLogDigest.slice(0, 16) + '\u2026');
      ok('and the counts signed are the ones the lookup found, 3 and 1',
        ev3.citations === 3 && ev3.verified === 1);
      const signedCheck = await K.signCertificate(
        await K.buildCertificate(checkedFields), await K.demoSigningKeys());
      const vCheck = await K.verifyCertificate(signedCheck);
      const claim3 = vCheck.claims.find((c) => c.id === 'citations-verified');
      ok('a certificate whose citations did not all check out FAILS claim 3, honestly',
        claim3.ok === false && /unverified/.test(claim3.missing.join(' ')),
        claim3.missing.join('; '));
      ok('the rest of the certificate is untouched by that: it is one claim that fails, '
        + 'not a broken certificate',
        vCheck.signature === true && vCheck.rootOK === true
          && vCheck.claims.filter((c) => c.ok).length === 3);

      // Offline is not a degraded mode, it is the mode the demo ships in.
      const untouched = await K.certFieldsFrom(() => '');
      ok('with no check at all the demo still signs, with its own stand-in digest',
        /^[0-9a-f]{64}$/.test(untouched.evidence['citations-verified'].retrievalLogDigest)
          && untouched.evidence['citations-verified'].retrievalLogDigest
            !== RECORDED.retrievalLogDigest);

      // The control itself, in the form the reader is handed.
      const cform = K.certFormHTML(K.CERT_DEFAULTS);
      ok('the form carries the checker: a passage box, a check button and a restart',
        cform.indexOf('id="ct-citetext"') >= 0 && cform.indexOf('id="ct-citecheck"') >= 0
          && cform.indexOf('id="ct-citereset"') >= 0 && cform.indexOf('id="ct-citeout"') >= 0);
      ok('the example in the box is the one that carries the fabricated citation',
        cform.indexOf('925 F.3d 1339') >= 0 && cform.indexOf('Mata v. Avianca') >= 0);
      ok('the licence key box carries the public demo key and does not remember it',
        /id="ct-citekey"[^>]*value="blf_lk_demo_bailment_law_free"/.test(cform)
          && /id="ct-citekey"[^>]*autocomplete="off"/.test(cform));
      ok('the form says the passage goes to CourtListener and to no model',
        cform.indexOf('to CourtListener and to nowhere else') >= 0
          && cform.indexOf('No model sees it') >= 0);
      ok('the typed counts are still offered, and still marked as unchecked assertions',
        cform.indexOf('id="ct-cites"') >= 0 && cform.indexOf('id="ct-cverified"') >= 0
          && cform.indexOf('nothing has checked them') >= 0);

      // Node only: locked counts and the three verdict states are a CSS fact.
      let citecss = '';
      if (typeof require === 'function' && typeof __dirname === 'string') {
        try { citecss = require('fs').readFileSync(require('path').join(__dirname, 'app.css'), 'utf8'); }
        catch { citecss = ''; }
      }
      // Node only: every control the checker wires up has to exist in the form it is
      // wired into. A typo in an id throws inside ctRender and takes the rest of the
      // builder's wiring with it, and no amount of pure-function testing would see it.
      let citesrc = '';
      if (typeof require === 'function' && typeof __dirname === 'string') {
        try { citesrc = require('fs').readFileSync(require('path').join(__dirname, 'certificate.js'), 'utf8'); }
        catch { citesrc = ''; }
      }
      if (citesrc) {
        const wired = (citesrc.match(/#ct-cite[a-z-]*/g) || [])
          .map((s) => s.slice(1)).filter((v, i, a) => a.indexOf(v) === i);
        const missing = wired.filter((id) => cform.indexOf('id="' + id + '"') < 0);
        ok('every #ct-cite\u2026 control the widget wires up exists in the form',
          wired.length >= 5 && missing.length === 0, wired.join(', '));
      }

      if (citecss) {
        ok('app.css marks a count filled in by a real lookup differently from a typed one',
          citecss.indexOf('.widget input.ct-locked{') >= 0);
        ok('each verdict has a colour AND a rule down the left, so it is not colour alone',
          /\.widget \.ct-cite-row\.ok\{border-left-color/.test(citecss)
            && /\.widget \.ct-cite-row\.bad\{border-left-color/.test(citecss)
            && /\.widget \.ct-cite-row\.warn\{border-left-color/.test(citecss));
      }
    }

    /* ------------------------------------------------------ attestation */
    if (B.attestation) {
      group('Attestation');
      const A = B.attestation;
      const digest = C.hex(await C.sha256('retainer agreement'));
      const attKeys = A.demoSigningKeys ? await A.demoSigningKeys() : await C.generateSigningKey();
      const att = await A.buildAttestation({
        statement: A.defaultStatement('retainer agreement', 'Doe v. Acme Holdings', '2026-09-14'),
        digest, recipient: 'Judge Washoe', purpose: 'In camera authenticity review',
        expiry: new Date(Date.now() + 14 * 864e5).toISOString(),
        signerName: 'Kevin G. Mohr, Esq.', signerBar: 'Bar No. 123456', signerJurisdiction: 'Washington',
      });
      const signedAtt = await A.signAttestation(att, attKeys);
      const good = await A.verifyAttestation(signedAtt, { reader: 'Judge Washoe', digest });
      ok('the named reader, in time, with the right copy: holds', good.ok);
      const wrongReader = await A.verifyAttestation(signedAtt, { reader: 'Opposing Counsel' });
      ok('a different reader is told "issued to X, not to you", not "invalid"',
        wrongReader.recipientMatch === false && wrongReader.signature === true
          && wrongReader.findings.some((f) => /not to you/.test(f.label)),
        wrongReader.findings.find((f) => /not to you/.test(f.label)).label);
      const late = await A.verifyAttestation(signedAtt, {
        reader: 'Judge Washoe', now: new Date(Date.now() + 30 * 864e5) });
      ok('past expiry it reports "expired on <date>", and says the signature still checks',
        late.expired === true && late.signature === true
          && late.findings.some((f) => /^Expired on /.test(f.label)),
        late.findings.find((f) => /^Expired on /.test(f.label)).label);
      const wrongCopy = await A.verifyAttestation(signedAtt, {
        reader: 'Judge Washoe', digest: C.hex(await C.sha256('a different document')) });
      ok('a different copy of the document is caught', wrongCopy.digestMatch === false);
      const swapped = JSON.parse(JSON.stringify(signedAtt));
      swapped.att.recipient = 'Opposing Counsel';
      // Renamed (C-17): this shows that EDITING the recipient after signing is detected.
      // It says nothing about a forger, who re-signs the whole payload with their own key.
      ok('editing the recipient after signing breaks the signature',
        (await A.verifyAttestation(swapped, { reader: 'Opposing Counsel' })).signature === false);
      const rk = await C.generateReaderKey();
      const env = await A.sealAttestation(signedAtt, await C.readerCode(rk.publicKey));
      const opened = await A.openSealed(env, rk.privateKey);
      // Renamed (C-17): the reader's NAME is not involved in the seal at all. What is
      // tested is that the holder of the matching private key can open the envelope.
      ok('tier 2: sealed, then opened by the holder of the reader key (the name is not what locks it)',
        opened.att.document.digest === digest);
      ok('tier 2: anyone else is refused',
        await A.openSealed(env, (await C.generateReaderKey()).privateKey).then(() => false, () => true));
    }

    /* --------------------------------------------------------- protocol */
    if (B.protocol) {
      group('Protocol root');
      const P = B.protocol;
      const commitments = [];
      for (let i = 0; i < 23; i++) commitments.push(await C.commit(enc('comm ' + i), C.randomNonce(32)));
      const docTree = await P.periodTree(commitments);
      const firmRoots = [await C.sha256('firm A'), docTree.root, await C.sha256('firm C'), await C.sha256('firm D')];
      const netTree = await P.periodTree(firmRoots);
      const net = netTree.root;
      const proof = await P.documentProof(docTree, 7, netTree, 1);
      const r = await P.verifyDocumentProof(commitments[7], proof, net);
      ok('a document proves through the firm root into the published network root', r.ok,
        proof.leafProof.length + ' + ' + proof.firmProof.length + ' sibling hashes');
      const outsider = await C.commit(enc('never batched'), C.randomNonce(32));
      ok('a document that was not batched cannot be proved in',
        (await P.verifyDocumentProof(outsider, proof, net)).ok === false);
      const oneTree = await P.periodTree([commitments[0]]);
      ok('the published root is 32 bytes whether the period held 1 document or 23',
        C.hex(net).length === 64 && C.hex(oneTree.root).length === 64);

      // C-06 / A-4, pinned. The demo now mirrors client_protocol.compact: fixed
      // MerkleTreePath<8>. Against the unpadded code every assertion below fails.
      ok('a period tree is always the contract\u2019s fixed depth',
        docTree.depth === 8 && docTree.slots.length === 256 && oneTree.slots.length === 256,
        docTree.slots.length + ' slots, depth ' + docTree.depth);
      const lengths = new Set();
      for (const n of [0, 1, 2, 23, 200]) {
        const ls = [];
        for (let i = 0; i < n; i++) ls.push(await C.sha256('c ' + i));
        const t = await P.periodTree(ls);
        lengths.add((await C.merkleProof(t.slots, 0)).length);
      }
      ok('every inclusion proof is the same length: the batch size cannot be read off it',
        lengths.size === 1 && lengths.has(8), '{' + [...lengths].join(',') + '} steps for n = 0,1,2,23,200');
      ok('a document proof is a constant 16 steps, both trees together',
        proof.leafProof.length + proof.firmProof.length === 16);
      const slotsSeen = new Set();
      for (let i = 0; i < 8; i++) slotsSeen.add((await P.periodTree([commitments[0]])).positions[0]);
      ok('the leaf slot is random, so the side bits do not spell out a position in the batch',
        slotsSeen.size > 1, 'first-leaf slots seen: ' + [...slotsSeen].join(', '));
      // A-5: an empty period still publishes.
      const empty = await P.periodTree([]);
      ok('a period with nothing in it still produces a root',
        C.hex(empty.root).length === 64 && empty.positions.length === 0);
      ok('two empty periods do not publish the same root',
        C.hex(empty.root) !== C.hex((await P.periodTree([])).root));
      ok('the Protocol copy about disclosure is true of the padded tree',
        /same length/i.test(P.PROOF_DISCLOSURE) && /not how many of either/i.test(P.PROOF_DISCLOSURE)
          && /same firm in the same period/i.test(P.PROOF_DISCLOSURE));
    }

    report('', null, '');
    report(`${pass} passed, ${fail} failed`, fail === 0, '');
    return { pass, fail };
  }

  root.Bailee.selftest = { run };
})(typeof globalThis !== 'undefined' ? globalThis : this);
