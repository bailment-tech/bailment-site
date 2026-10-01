(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const { sha256, hex, unhex, canonical, digestJSON, merkleRoot, merkleProof, verifyProof, generateSigningKey, signJSON, verifyJSON, exportPublicKey, importPublicKey, importPrivateKey, b64url, unb64url, keyFingerprint, utf8Decode } = root.Bailee.crypto;
  const { mount, $, esc, wireCopy, monoBlock, row, nowISO, fmtDate, short,
    loadRegistry, registrySigner, registryPipeline, wmValue, wireFields,
    WM_OWN, WM_OWN_LABEL, help } = root.Bailee.ui;

  // The certificate a court can check: four claims, signed, verifiable by anyone
  // holding the public key. The document itself is never revealed.
  const CERT_TYPE = 'bailment.ai/certificate/v1';

  // The four claims, in the order the plan states them, with the evidence each one needs.
  const CLAIM_SPEC = [
    { id: 'model-manifest',
      title: 'Which model, version and provider touched the text',
      proof: 'Signed model manifest pinned in the appliance\u2019s licensed configuration',
      required: ['model', 'version', 'provider', 'manifestDigest'] },
    { id: 'attorney-adoption',
      title: 'A named, licensed attorney reviewed and adopted it before filing',
      proof: 'The send record. Nothing reaches a client or a filing without a send',
      required: ['attorney', 'barNumber', 'jurisdiction', 'sendRecordDigest', 'adoptedAt'] },
    { id: 'citations-verified',
      title: 'Every citation was independently verified',
      proof: 'Required pipeline step, recorded as completed against the retrieval log',
      required: ['citations', 'verified', 'retrievalLogDigest', 'pipelineStep'] },
    { id: 'no-identifier',
      title: 'No client identifier reached a model',
      proof: 'Template and vault split, with the redaction artifact version recorded',
      required: ['redactorVersion', 'templateVaultSplit', 'identifiersReachedModel'] },
  ];

  // The firm is not a choice. A real deployment reads it out of the licence, so the demo
  // shows one fixed made-up firm rather than a dropdown nobody would ever use.
  const DEMO_FIRM = 'Bailment Law';

  // "Not stated" as a value, not as a hole. An empty string fails CLAIM_SPEC's required
  // check and the certificate comes back broken; 'N/A' records, truthfully, that nothing
  // was claimed here. Every dropdown that a real deployment would not fill in for you
  // carries it.
  const NA = 'N/A';

  // Demo choices, not facts. The first entry of each list is what the demo opens with.
  // Each list is a single <select> that ends with "N/A" and then "Write my own": choosing
  // "Write my own" opens one empty box inside the same field. There is no second control
  // beside the dropdown, because two controls for one answer is two chances to be wrong.
  // Astra 6 and Opus 5.1 do not exist. They are here on purpose: the certificate records
  // the model name it is given, and naming a model is not proof that one ran.
  const CERT_OPTIONS = {
    court: ['Second Judicial District Court, Washoe County, Nevada'],
    judge: ['Judge Washoe'],
    filing: ['Motion for Summary Judgment', 'Opposition to Motion to Dismiss', 'Trial Brief'],
    model: ['Llama 3.3 70B Instruct', 'Qwen 2.5 72B', 'In House Model', 'Astra 6', 'Opus 5.1'],
    provider: ['Meta (self-hosted, firm appliance)', 'Alibaba (self-hosted, firm appliance)'],
    jurisdiction: ['Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado',
      'Connecticut', 'Delaware', 'District of Columbia', 'Florida', 'Georgia', 'Hawaii',
      'Idaho', 'Illinois', 'Indiana', 'Iowa', 'Kansas', 'Kentucky', 'Louisiana', 'Maine',
      'Maryland', 'Massachusetts', 'Michigan', 'Minnesota', 'Mississippi', 'Missouri',
      'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey', 'New Mexico',
      'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon',
      'Pennsylvania', 'Rhode Island', 'South Carolina', 'South Dakota', 'Tennessee',
      'Texas', 'Utah', 'Vermont', 'Virginia', 'Washington', 'West Virginia', 'Wisconsin',
      'Wyoming'],
    redactor: ['bailee-redactor 4.2.1 (signed)', 'bailee-redactor 5.0.0-rc1 (signed)'],
    pipelineStep: ['cite-check@2026.9.3', 'cite-check@2026.8.1', 'redact-verify@2026.9.3'],
  };

  // The build that goes with each listed model, so the reader never types a version.
  // A model the list does not carry has no version we could honestly supply: the box is
  // left empty and the reader fills it, or it is recorded as N/A.
  // Nothing fills the version in any more: the build that ran is the reader's to state,
  // and a version we guessed for them would be the certificate asserting something nobody
  // checked. Kept as a function so the shape of the API does not move.
  const MODEL_VERSIONS = {};
  const modelVersion = (name) => MODEL_VERSIONS[String(name || '').trim()] || '';

  // Shown in the box as a hint, never as a value, and never signed. A placeholder is a
  // hint, not an answer: putting someone else's example name on a court document is the
  // worst default this form could have, so a box left empty records N/A instead.
  const EXAMPLES = {
    caseNumber: '2:26-cv-01184',
    attorney: 'Perry Masonry, Esq.',
    barNumber: 'Bar No. 123456',
  };

  // ------------------------------------------------- claim 3, actually checked
  // The two numbers under claim 3 used to be whatever somebody typed. The appliance can
  // check them: POST /v1/citations/check extracts every citation in a passage and looks
  // each one up against CourtListener's opinion database.
  //
  // This example passage is the product in three lines. One citation that exists, one
  // that does not, and Varghese v. China Southern Airlines \u2014 the case a New York
  // lawyer cited in Mata v. Avianca, which a model had invented, and which cost him
  // sanctions. A cite-checker that cannot catch that one is decoration.
  const CITE_EXAMPLE = 'The right recognised in Obergefell v. Hodges, 576 U.S. 644 (2015), '
    + 'controls. See also Smith v. Tri-State Logistics, 678 F. Supp. 3d 443 (S.D.N.Y. 2023), '
    + 'and Varghese v. China Southern Airlines Co., 925 F.3d 1339 (11th Cir. 2019).';
  const CITE_CORRECTED = 'The right recognised in Obergefell v. Hodges, 576 U.S. 644 (2015), controls.';

  // With no appliance running, the demo answers the example passage from a recorded
  // CourtListener lookup, so the reader still sees the bad cites caught and corrected.
  const OBERGEFELL_HIT = { citation: '576 U.S. 644', status: 200, found: true, verdict: 'verified',
    note: '', clusters: [{ id: 2812209, caseName: 'Obergefell v. Hodges', court: '',
      dateFiled: '2015-06-26', absolute_url: '/opinion/2812209/obergefell-v-hodges/' }] };
  const DEMO_LOOKUPS = {
    [CITE_EXAMPLE]: [OBERGEFELL_HIT,
      { citation: '678 F. Supp. 3d 443', status: 404, found: false, verdict: 'not found',
        note: 'No case at this cite.', clusters: [],
        fix: 'Smith v. Tri-State Logistics is not a reported case. Strike the "See also".' },
      { citation: '925 F.3d 1339', status: 404, found: false, verdict: 'not found',
        note: 'No case at this cite.', clusters: [],
        fix: 'Varghese v. China Southern Airlines was invented by a model and filed in Mata v. '
          + 'Avianca (S.D.N.Y. 2023), where the lawyers were sanctioned. Strike it.' }],
    [CITE_CORRECTED]: [OBERGEFELL_HIT],
  };
  async function demoCitationCheck(text) {
    const citations = DEMO_LOOKUPS[String(text || '').trim()];
    if (!citations) return null;
    const verified = citations.filter((c) => c.status === 200).length;
    return { checked: true, demo: true, source: 'courtlistener/v4 citation-lookup (recorded)',
      citations, total: citations.length, verified, unverified: citations.length - verified,
      corrected: verified < citations.length ? CITE_CORRECTED : null,
      retrievalLogDigest: hex(await sha256(canonical(citations))) };
  }

  // The appliance, not a cloud. The default is the one a reader running the backend
  // beside this page already has; anything else they type is their own deployment.
  const CITE_BASE = 'http://127.0.0.1:8402';
  const COURTLISTENER = 'https://www.courtlistener.com';

  // The per-citation `status` the API answers with, in the words the page prints. Only
  // 200 with a matching case counts as verified; 300 means the citation matches more
  // than one case, which is an answer and not a verification.
  const CITE_VERDICTS = {
    200: { label: 'verified', cls: 'ok' },
    300: { label: 'ambiguous', cls: 'warn' },
    400: { label: 'unreadable', cls: 'bad' },
    404: { label: 'not found', cls: 'bad' },
  };

  // Plain-English explainers behind the little "?" next to the harder labels. One or two
  // sentences: what the thing is, and why a court would care. Hover or keyboard focus
  // both reveal them (app.css), and each one is wired to its control by aria-describedby.
  const HELP = {
    model: 'The certificate records the model name it is given. Naming a model is not proof that '
      + 'one ran \u2014 Astra 6 and Opus 5.1 do not exist, and this demo will sign either of them '
      + 'just as readily.',
    provider: 'Optional. Pick N/A if nobody outside the firm supplied the model.',
    specificCourt: 'Optional. Recorded alongside the state when you want to be exact.',
    attorneyFields: 'Nothing here is pre-filled. The greyed-out names are placeholders, not '
      + 'answers \u2014 type over them. Left empty, they are recorded as N/A, never as the example '
      + 'shown, and you are told which ones before anything is signed.',
    documentDigest: 'A SHA-256 fingerprint of the finished filing. It is what ties this '
      + 'certificate to one exact document: change a comma and the fingerprint changes, so a '
      + 'court can tell whether the filing in front of it is the one that was certified. '
      + 'Paste the digest the notarize step gave you. Left empty, this demo computes a stand-in '
      + 'digest from fixed demo text: a certificate whose digest is not 64 hex characters is '
      + 'bound to no document at all.',
    version: 'The exact build of the model that ran \u2014 quantisation and release date, not just '
      + 'the family name. Two builds of the same model can answer differently, so a court asking '
      + 'whether this output could have come from that model needs the build, not the brand. '
      + 'It fills in from the model you pick; overwrite it if your build differs, and left empty '
      + 'it is recorded as N/A.',
    manifestDigest: 'A fingerprint of the signed model manifest the appliance was running. It '
      + 'lets anyone confirm later that the configuration described here is the one that was '
      + 'actually pinned, and that it was not swapped after the fact.',
    sendRecordDigest: 'A fingerprint of the send record \u2014 the moment a named attorney released '
      + 'the document to a client or a court. It is the evidence that a licensed human adopted '
      + 'the work before it left the firm, rather than a model filing by itself.',
    retrievalLogDigest: 'A fingerprint of the retrieval log: every source the pipeline actually '
      + 'fetched while checking the citations. It is what turns "we checked the cites" into '
      + 'something an opponent can test instead of a sentence they have to believe.',
    pipelineStep: 'The named step that performed the citation check, with its version. A court '
      + 'cares which checker ran, because "a check was done" is not a fact until you can say '
      + 'which one did it and when.',
    redactorVersion: 'The build of the redaction tool that split the text from the client '
      + 'identifiers. Redactors have bugs and bugs have version numbers, so recording the build '
      + 'is what makes the no-identifier claim auditable years later.',
    identifiersReachedModel: 'How many client identifiers \u2014 names, matter numbers, account '
      + 'numbers \u2014 were present in the text the model saw. The claim is that this is zero: the '
      + 'model worked on a template while the identifiers stayed in the firm\u2019s vault.',
    citationCheck: 'The appliance pulls every citation out of this passage and looks each one up '
      + 'in CourtListener. The example carries three: one real, one that does not exist, and '
      + 'Varghese v. China Southern Airlines \u2014 the citation a model invented, a lawyer filed in '
      + 'Mata v. Avianca, and a judge sanctioned him for. '
      + 'The appliance reads the passage, pulls every citation out of it and looks '
      + 'each one up in CourtListener\u2019s opinion database. The passage goes to CourtListener '
      + 'and nowhere else: no model sees it, here or on the server. A citation that resolves to '
      + 'no case is reported as not found rather than quietly counted.',
  };

  const CERT_DEFAULTS = {
    court: 'Second Judicial District Court, Washoe County, Nevada',
    judge: 'Judge Washoe',
    caseNumber: 'Case - 123456',
    filing: 'Motion for Summary Judgment',
    firm: DEMO_FIRM,
    documentDigest: '',
    registryEntry: 'bailee-pipeline/2026.9.3',
    licenseExpires: '',
    evidence: {
      'model-manifest': { model: 'Llama 3.3 70B Instruct', version: 'Version 1234',
        provider: 'Meta (self-hosted, firm appliance)', manifestDigest: '' },
      'attorney-adoption': { attorney: EXAMPLES.attorney, barNumber: EXAMPLES.barNumber,
        jurisdiction: 'Nevada', sendRecordDigest: '', adoptedAt: '' },
      'citations-verified': { citations: 14, verified: 14, retrievalLogDigest: '',
        pipelineStep: 'cite-check@2026.9.3' },
      'no-identifier': { redactorVersion: 'bailee-redactor 4.2.1 (signed)',
        templateVaultSplit: true, identifiersReachedModel: 0 },
    },
  };


  // Every control the reader can leave empty, in the order the form shows them, with the
  // label the warning names it by — the SAME words the form prints above the control,
  // pinned by the self-check so the two cannot drift apart.
  //
  // `records` is what a blank one is signed as. It is N/A everywhere except:
  //   - the document digest, which has to be 64 hex characters or the certificate is not
  //     readable at all (certificateShapeError), so the demo computes a stand-in;
  //   - the three counts, which are numbers on the wire and fall back to the demo's own
  //     visible defaults rather than to a string.
  // Both exceptions are still listed in the warning, saying exactly what they record.
  const BLANKABLE = [
    { name: 'court', id: 'ct-court', label: 'Court' },
    { name: 'judge', id: 'ct-judge', label: 'Judge' },
    { name: 'caseNumber', id: 'ct-case', label: 'Case number' },
    { name: 'filing', id: 'ct-filing', label: 'Filing' },
    { name: 'documentDigest', id: 'ct-digest',
      label: 'Document digest (SHA-256, from the notarize step)',
      records: 'a stand-in digest computed from fixed demo text' },
    { name: 'model', id: 'ct-model', label: 'Model' },
    { name: 'version', id: 'ct-modelver', label: 'Version' },
    { name: 'provider', id: 'ct-provider', label: 'Provider (optional)' },
    { name: 'attorney', id: 'ct-atty', label: 'Attorney' },
    { name: 'barNumber', id: 'ct-bar', label: 'Bar number' },
    { name: 'jurisdiction', id: 'ct-juris', label: 'Jurisdiction (state)' },
    { name: 'specificCourt', id: 'ct-court-specific', label: 'Specific court (optional)' },
    { name: 'citations', id: 'ct-cites', label: 'Citations in the filing',
      records: String(CERT_DEFAULTS.evidence['citations-verified'].citations) },
    { name: 'verified', id: 'ct-cverified', label: 'Independently verified',
      records: String(CERT_DEFAULTS.evidence['citations-verified'].verified) },
    { name: 'pipelineStep', id: 'ct-pipestep', label: 'Pipeline step' },
    { name: 'redactorVersion', id: 'ct-redactor', label: 'Redactor version' },
    { name: 'identifiersReachedModel', id: 'ct-leaked',
      label: 'Identifiers that reached a model',
      records: String(CERT_DEFAULTS.evidence['no-identifier'].identifiersReachedModel) },
  ];

  // The same `get(name)` the signer is driven with, so the warning can never disagree
  // with what is about to be signed: one read of the form answers both questions.
  function blankFields(get) {
    return BLANKABLE
      .filter((f) => String(get(f.name) == null ? '' : get(f.name)).trim() === '')
      .map((f) => ({ name: f.name, id: f.id, label: f.label, records: f.records || NA }));
  }

  async function fakeDigest(label) { return hex(await sha256(label + '|demo-evidence')); }

  // One place where a filled-in form becomes the fields a certificate is built from.
  // `get(name)` returns a string for one control and knows nothing about the DOM, so the
  // page and the self-check drive exactly the same code. Anything the reader typed
  // through "Write my own" arrives here as an ordinary string and is never re-derived
  // from the option list: that is the path that must survive into the signed payload.
  //
  // Empty is not allowed to become a hole, and it is never allowed to become somebody
  // else's example. CLAIM_SPEC requires every evidence field, so one rule covers the
  // whole form: a field left blank at issue time is recorded as the string 'N/A'. The
  // greyed-out text in a box is a hint and is never signed.
  async function certFieldsFrom(get) {
    const g = (name) => String(get(name) == null ? '' : get(name)).trim();
    const num = (name, dflt) => {
      const v = g(name); const n = Number(v);
      return v === '' || isNaN(n) ? dflt : n;
    };
    const d = JSON.parse(JSON.stringify(CERT_DEFAULTS));
    const D = CERT_DEFAULTS.evidence;
    d.court = g('court') || NA;
    d.judge = g('judge') || NA;
    d.caseNumber = g('caseNumber') || NA;     // never EXAMPLES.caseNumber — that is a hint
    d.filing = g('filing') || NA;
    d.firm = DEMO_FIRM;                       // from the licence, never from a control
    d.documentDigest = g('documentDigest') || await fakeDigest(d.filing);
    d.licenseExpires = new Date(Date.now() + 45 * 864e5).toISOString();

    const e = d.evidence;
    e['model-manifest'].model = g('model') || NA;
    // The box is filled in from the model, so reading the box IS reading the model's
    // version. Cleared on purpose, it records N/A rather than a version nobody claimed.
    e['model-manifest'].version = g('version') || NA;
    e['model-manifest'].provider = g('provider') || NA;
    e['model-manifest'].manifestDigest = await fakeDigest('manifest');

    // The placeholders here name a lawyer who does not exist. Signing that onto a court
    // document because a box was left empty is the worst default available, so blank is
    // recorded as N/A and the reader is warned by name before it happens.
    e['attorney-adoption'].attorney = g('attorney') || NA;
    e['attorney-adoption'].barNumber = g('barNumber') || NA;
    // The specific court is optional, so a blank one used to vanish. Vanishing is not
    // the same as saying nothing: it is recorded as N/A beside the state.
    const state = g('jurisdiction') || NA, specific = g('specificCourt') || NA;
    e['attorney-adoption'].jurisdiction = (state === NA && specific === NA)
      ? NA                                    // nothing stated at all reads as one N/A
      : state + ' \u2014 ' + specific;
    e['attorney-adoption'].sendRecordDigest = await fakeDigest('send-record');
    e['attorney-adoption'].adoptedAt = nowISO();

    e['citations-verified'].citations = num('citations', D['citations-verified'].citations);
    e['citations-verified'].verified = num('verified', D['citations-verified'].verified);
    // A real check supplies the digest of the retrieval log it produced, and that is what
    // gets signed. With no check there is no log, so the demo's stable, meaningless
    // stand-in is used and the page says so beside it.
    e['citations-verified'].retrievalLogDigest = g('retrievalLogDigest')
      || await fakeDigest('retrieval-log');
    e['citations-verified'].pipelineStep = g('pipelineStep') || NA;
    // What the filer said, beside what the check found. `assertedCitations` and
    // `assertedVerified` are empty unless a real lookup replaced numbers somebody had
    // already typed, and they carry the numbers that were typed. No assertion, no
    // block — CERT_DEFAULTS carries none, and one is never manufactured from the
    // measured pair.
    delete e['citations-verified'].asserted;
    const asserted = assertedBlock(
      { citations: get('assertedCitations'), verified: get('assertedVerified') },
      e['citations-verified']);
    if (asserted) e['citations-verified'].asserted = asserted;

    e['no-identifier'].redactorVersion = g('redactorVersion') || NA;
    e['no-identifier'].identifiersReachedModel = num('identifiersReachedModel', 0);
    return d;
  }

  // A certificate is only a pass if it was signed by a key listed in registry.json.
  // So that the demo can still show a pass, it signs with a demo key whose public half
  // is in that registry. The private half is printed here in full, on purpose: this is
  // a demonstration, anyone can sign with it, and a key anyone can use proves nothing
  // about who signed. In production this key lives in the attestation service under the
  // 3-of-5 root and never appears in a page.
  const DEMO_SIGNER = {
    id: 'demo-attestation-service',
    spki: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt6ZGDXumjls6Ld5EnjgJ3n4R57W_XIo7-VQJCv8b-hv7CYxJqtgMvehXQz_HugnJlDOxW0gvo8lp2Y521y5-XQ',
    pkcs8: 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvlil0XhF_wAB63auuDNg6MdiXE48_imXgz9FnUw6N9OhRANCAAS3pkYNe6aOWzot3kSeOAnefhHntb9cijv5VAkK_xv6G_sJjEmq2Ay96FdDP8e6CcmUM7FbSC-jyWnZjnbXLn5d',
  };

  let demoKeysPromise = null;
  function demoSigningKeys() {
    if (!demoKeysPromise) {
      demoKeysPromise = (async () => ({
        privateKey: await importPrivateKey(DEMO_SIGNER.pkcs8),
        publicKey: await importPublicKey(DEMO_SIGNER.spki),
      }))();
    }
    return demoKeysPromise;
  }

  // Real certificates carry exactly the four claims in CLAIM_SPEC. The cap is here so a
  // hostile fragment cannot hand the page thousands of leaves to hash.
  const MAX_CLAIMS = CLAIM_SPEC.length;
  const HEX64 = /^[0-9a-f]{64}$/i;

  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';
  const parses = (v) => nonEmpty(v) && !isNaN(new Date(v));

  // Shape first, trust second. Everything below runs before a signature is checked and
  // before a single hash is computed, so a malformed payload costs nothing and is
  // reported as "not readable" rather than thrown.
  function certificateShapeError(payload) {
    if (!isObj(payload)) return 'That is not a certificate payload.';
    const { cert, sig, pub } = payload;
    if (!isObj(cert) || cert.type !== CERT_TYPE) return 'Not a Bailee certificate.';
    if (!nonEmpty(sig) || !nonEmpty(pub)) return 'The signature or the public key is missing.';
    if (!parses(cert.issued)) return 'The issue date is missing or unreadable.';

    if (!isObj(cert.issuer) || !nonEmpty(cert.issuer.name) || !nonEmpty(cert.issuer.registryEntry)) {
      return 'The issuer block is missing: a certificate must name the service and the pipeline version that made it.';
    }
    if (!isObj(cert.license) || !nonEmpty(cert.license.firm)) return 'The licence block is missing the licensed firm.';
    if (!parses(cert.license.expires)) return 'The licence has no readable expiry date, so there is no licence window to check.';
    if (!isObj(cert.filing) || !nonEmpty(cert.filing.court) || !nonEmpty(cert.filing.caseNumber)) {
      return 'The filing block is missing the court or the case number.';
    }
    if (!isObj(cert.document) || !HEX64.test(String(cert.document.digest || ''))) {
      return 'No document digest. A certificate bound to no document certifies nothing.';
    }
    if (!HEX64.test(String(cert.claimsRoot || ''))) return 'The claims root is missing or is not a SHA-256 digest.';

    if (!Array.isArray(cert.claims)) return 'The claims list is missing.';
    if (cert.claims.length === 0) return 'The claims list is empty. There is nothing to check.';
    if (cert.claims.length > MAX_CLAIMS) {
      return `${cert.claims.length} claims. A Bailee certificate carries exactly ${MAX_CLAIMS}; this one was not read.`;
    }
    const want = CLAIM_SPEC.map((s) => s.id);
    const got = cert.claims.map((c) => (isObj(c) ? c.id : null));
    for (const c of cert.claims) if (!isObj(c) || !isObj(c.evidence)) return 'A claim is missing its evidence block.';
    const missing = want.filter((id) => got.filter((g) => g === id).length !== 1);
    if (missing.length) {
      return `A certificate makes all four claims. This one is missing or duplicates: ${missing.join(', ')}.`;
    }
    return null;
  }


  // ---------------------------------------------------------------- build

  async function buildCertificate(f) {
    const claims = CLAIM_SPEC.map((spec) => ({
      id: spec.id,
      title: spec.title,
      provedBy: spec.proof,
      evidence: f.evidence[spec.id],
    }));
    const claimDigests = [];
    for (const c of claims) claimDigests.push(await digestJSON(c));
    const root = await merkleRoot(claimDigests);
    return {
      type: CERT_TYPE,
      issued: f.issued || nowISO(),
      issuer: { name: 'Bailment attestation service', registryEntry: f.registryEntry },
      license: { firm: f.firm, expires: f.licenseExpires },
      filing: { court: f.court, judge: f.judge, caseNumber: f.caseNumber, title: f.filing },
      document: { digest: f.documentDigest },
      claims,
      claimsRoot: hex(root),
    };
  }

  async function signCertificate(cert, keys) {
    return {
      k: 'certificate',
      cert,
      sig: await signJSON(keys.privateKey, cert),
      pub: await exportPublicKey(keys.publicKey),
    };
  }

  function encodePayload(p) { return b64url(new TextEncoder().encode(JSON.stringify(p))); }
  function decodePayload(s) { return JSON.parse(utf8Decode(unb64url(String(s).trim().replace(/^.*#(?:[ca]=)?/, '')))); }
  const VERIFY_BASE = 'https://verify.bailment.tech/';   // published shape
  function certificateURL(p, base = 'verify.html') { return `${base}#c=${encodePayload(p)}`; }

  // --------------------------------------------------------------- verify

  // Three outcomes, never two:
  //   'verified'     signature by a key in the registry, approved pipeline, every check met
  //   'unregistered' the arithmetic all checks out, but the key is not one we can name
  //   'fail'         a check failed
  //   'unreadable'   the payload is not a certificate we can read at all
  // `ok` is true only for 'verified'. Nothing in the payload can make a key registered.
  //
  // opts: { now, digest, caseNumber, registry }. A bare Date is accepted for the old
  // verifyCertificate(payload, now) call shape.
  async function verifyCertificate(payload, opts = {}) {
    const o = (opts instanceof Date || typeof opts === 'string' || typeof opts === 'number')
      ? { now: opts } : (opts || {});
    const now = o.now ? new Date(o.now) : new Date();

    const shapeError = certificateShapeError(payload);
    if (shapeError) {
      return { ok: false, status: 'unreadable', state: 'fail', quarantine: true,
        fatal: shapeError, headline: 'Not readable', claims: [], checks: [], findings: [] };
    }

    const { cert, sig, pub } = payload;
    const out = { claims: [], checks: [], notes: [] };
    out.licenseeFirm = cert.license.firm;
    out.registryEntry = cert.issuer.registryEntry;

    let key;
    try { key = await importPublicKey(pub); }
    catch {
      return { ok: false, status: 'unreadable', state: 'fail', quarantine: true,
        fatal: 'The public key in this payload is not a readable P-256 key.',
        headline: 'Not readable', claims: [], checks: [], findings: [] };
    }
    out.fingerprint = await keyFingerprint(pub);
    out.signature = await verifyJSON(key, sig, cert);

    // --- the trust root. Loaded from registry.json, never from the payload.
    const loaded = o.registry ? { registry: o.registry, source: 'supplied', error: null } : await loadRegistry();
    out.registrySource = loaded.source;
    out.registryError = loaded.error;
    const signer = registrySigner(loaded.registry, {
      spki: pub, fingerprint: out.fingerprint, at: cert.issued, signs: 'certificate' });
    out.registeredSigner = signer;
    // Listed is about the key; registered is about this certificate. A key can be listed
    // while the certificate it came with proves nothing, because the signature failed.
    out.keyListed = !!(signer && signer.live);
    out.registered = out.keyListed && out.signature === true;
    out.signerWindowOK = signer ? signer.live : null;
    // The issuer the payload names, against the name the registry records for that key.
    // `cert.license.firm` is the licensee, a different party, and is not in the registry.
    out.issuerName = cert.issuer.name;
    out.signerNameMatch = out.keyListed
      ? String(cert.issuer.name).trim().toLowerCase() === String(signer.name || '').trim().toLowerCase()
      : null;

    const pipeline = registryPipeline(loaded.registry, cert.issuer.registryEntry, cert.issued);
    out.pipeline = pipeline;
    out.pipelineListed = !!(pipeline && pipeline.live);
    out.pipelineApproved = out.pipelineListed && out.signature === true;

    // --- claims
    const digests = [];
    for (const c of cert.claims) digests.push(await digestJSON(c));
    const root = hex(await merkleRoot(digests));
    out.rootOK = root === cert.claimsRoot;

    // TODO(crypto.js): swap to merkleProofs(leaves) once the other worker lands it —
    // one pass over the tree instead of one tree per claim. Capped at MAX_CLAIMS (4)
    // above, so the O(n^2) here is bounded at four proofs.
    const proofs = [];
    for (let i = 0; i < cert.claims.length; i++) proofs.push(await merkleProof(digests, i));

    for (let i = 0; i < cert.claims.length; i++) {
      const c = cert.claims[i];
      const spec = CLAIM_SPEC.find((s) => s.id === c.id);
      const missing = spec ? spec.required.filter((k) => {
        const v = c.evidence?.[k];
        return v === undefined || v === null || v === '';
      }) : ['unknown claim id'];
      const included = await verifyProof(digests[i], proofs[i], unhex(cert.claimsRoot));
      let detail = '';
      let asserted = null, assertionNote = '';
      if (c.id === 'citations-verified' && c.evidence) {
        // MEASURED ONLY. This arithmetic reads the two measured counts and nothing
        // else, whatever the filer asserted. An assertion can never make a claim pass,
        // and one that agrees with a failing measurement still fails.
        const { citations, verified } = c.evidence;
        detail = verified === citations
          ? `${verified} of ${citations} citations verified against the retrieval log`
          : `only ${verified} of ${citations} citations verified`;
        if (verified !== citations) missing.push('unverified citations');
        // Recorded, and now said out loud. A reader shown only "1 of 3 verified" never
        // learns that somebody signed their name to 14 of 14.
        if (c.evidence.asserted && typeof c.evidence.asserted === 'object') {
          asserted = c.evidence.asserted;
          assertionNote = assertionLine(c.evidence);
          if (assertionNote) detail = `${detail}. ${assertionNote}`;
        }
      }
      if (c.id === 'no-identifier' && c.evidence) {
        if (c.evidence.identifiersReachedModel !== 0) missing.push('identifiers reached a model');
        if (c.evidence.templateVaultSplit !== true) missing.push('template/vault split not applied');
        detail = `redactor ${c.evidence.redactorVersion}, ${c.evidence.identifiersReachedModel} identifiers reached a model`;
      }
      out.claims.push({
        id: c.id, title: c.title, provedBy: c.provedBy, evidence: c.evidence,
        ok: missing.length === 0 && included, included, missing, detail,
        asserted, assertionNote,
        digest: hex(digests[i]), proofLength: proofs[i].length,
      });
      if (assertionNote) out.assertionNote = assertionNote;
    }
    out.claimsComplete = out.claims.length === CLAIM_SPEC.length && out.claims.every((c) => c.ok);

    // --- the licence had to be live at the moment of issue. Expiry is the revocation path.
    const exp = new Date(cert.license.expires);
    out.licenseLive = new Date(cert.issued) <= exp;
    out.licenseExpired = now > exp;

    // --- binding to the copy in front of the reader. Only the reader can supply these.
    out.digestMatch = null;
    if (o.digest && String(o.digest).trim()) {
      out.digestMatch = String(o.digest).trim().toLowerCase() === String(cert.document.digest).toLowerCase();
    }
    out.caseMatch = null;
    if (o.caseNumber && String(o.caseNumber).trim()) {
      out.caseMatch = String(o.caseNumber).trim().toLowerCase() === String(cert.filing.caseNumber).trim().toLowerCase();
    }

    // --- verdict
    const broken = !out.signature || !out.rootOK || !out.claimsComplete || !out.licenseLive
      || out.digestMatch === false || out.caseMatch === false || out.signerNameMatch === false
      || !!(out.registeredSigner && !out.registeredSigner.live);
    if (broken) {
      out.status = 'fail';
      out.state = 'fail';
      out.headline = 'Certificate does not verify';
    } else if (!out.registered || !out.pipelineApproved) {
      out.status = 'unregistered';
      out.state = 'open';
      out.headline = 'Consistent but unregistered';
    } else {
      out.status = 'verified';
      out.state = 'pass';
      out.headline = 'Certificate verifies';
    }
    out.ok = out.status === 'verified';
    out.quarantine = out.signature !== true;
    return out;
  }

  // ------------------------------------------------------------------- UI

  // A "?" that explains itself. The button is a real <button>, so a keyboard reaches it;
  // the explanation is a sibling the CSS reveals on :hover and on :focus-visible, and
  // aria-describedby points the screen reader at the same words the mouse gets.
  function ctHelp(key) {
    return help(HELP[key], 'ct-help-' + key);
  }

  const ctLabel = (forId, text, help) => `<span class="wm-labelrow">`
    + `<label for="${esc(forId)}">${text}</label>${ctHelp(help)}</span>`;

  // One dropdown, one answer. "Write my own" is the last OPTION in the select, not a
  // button beside it: choosing it reveals the one empty box below and focuses it
  // (ui.wireFields does that, delegated, for every .wm-field on the page). The markup is
  // deliberately the shape ui.wmValue() already reads, so a typed value and a listed one
  // reach the signer by exactly the same path.
  //
  // spec: { id, label, options, value, help, hint, na, placeholder }
  function ctField(spec) {
    // A plain box with a sensible default in it. No dropdown, no arrow, no suggestion
    // window repeating what is already there: the reader reads the value and types over
    // it if it is wrong. CERT_OPTIONS still names the answers we consider sensible \u2014 the
    // first one is what the box starts with.
    const s = spec || {};
    const id = String(s.id);
    const opts = (s.options || []).map((o) => (typeof o === 'string' ? { value: o, label: o } : o));
    const value = s.value == null ? (opts[0] ? opts[0].value : '') : String(s.value);
    return `<div class="field wm-field" data-wm="${esc(id)}">`
      + (s.label ? ctLabel(id, esc(s.label), s.help) : '')
      + `<input class="wm-input wm-box" id="${esc(id)}" type="text"`
      + ` placeholder="${esc(s.placeholder || 'Type your own\u2026')}"`
      + ` aria-label="${esc(s.label || id)}" value="${esc(value)}">`
      + (s.hint ? `<p class="wm-hint">${s.hint}</p>` : '')
      + '</div>';
  }

  // A box the reader always types into: no dropdown, no options, nothing pre-filled.
  // The example only ever lives in the placeholder attribute.
  function ctText(spec) {
    const s = spec || {};
    const id = String(s.id);
    return `<div class="field wm-field">`
      + ctLabel(id, esc(s.label), s.help)
      + `<input class="wm-text${s.cls ? ' ' + esc(s.cls) : ''}" id="${esc(id)}" type="text"`
      + ` placeholder="${esc(s.placeholder || 'Type your own\u2026')}"`
      + (s.value ? ` value="${esc(s.value)}"` : '')
      + (s.inputmode ? ` inputmode="${esc(s.inputmode)}"` : '') + '>'
      + (s.hint ? `<p class="wm-hint">${s.hint}</p>` : '')
      + '</div>';
  }

  // --------------------------------------------------- the citation checker
  // Three pure functions and one call. The rendering is pure so the self-check can run
  // it over a recorded answer with no network, and the call takes its `fetch` as an
  // argument for the same reason.

  const citeVerdict = (entry) => CITE_VERDICTS[Number(entry && entry.status)]
    || { label: 'not checked', cls: 'bad' };

  // A found case links back to CourtListener, because "we checked" is worth nothing if
  // the reader cannot go and look at the same page we looked at.
  function citeCaseHTML(c) {
    const name = esc(c.caseName || 'an unnamed case');
    const when = c.dateFiled ? ' <span class="ct-cite-when">' + esc(String(c.dateFiled)) + '</span>' : '';
    const where = c.court ? ' <span class="ct-cite-court">' + esc(String(c.court)) + '</span>' : '';
    return c.absolute_url
      ? `<a class="ct-cite-case" href="${esc(COURTLISTENER + c.absolute_url)}" target="_blank"
          rel="noopener noreferrer">${name}</a>${where}${when}`
      : `<span class="ct-cite-case">${name}</span>${where}${when}`;
  }

  function citeRowHTML(entry) {
    const v = citeVerdict(entry);
    const found = (entry.clusters || []).map(citeCaseHTML).join(', ');
    const said = entry.note && !found ? `<span class="ct-cite-note">${esc(entry.note)}</span>` : '';
    const fix = entry.fix ? ` <span class="ct-cite-fix">Fix: ${esc(entry.fix)}</span>` : '';
    return `<li class="ct-cite-row ${v.cls}">
      <span class="ct-cite-cite">${esc(entry.citation || '')}</span>
      <span class="ct-cite-verdict">${esc(v.label)}</span>
      <span class="ct-cite-detail">${found || said}${fix}</span></li>`;
  }

  // One line that a reader can act on, whether the check ran or not. An answer that did
  // not happen never prints a count: the whole point of the fail-closed result is that
  // there is no number in it to misread.
  function citeResultHTML(result) {
    const r = result || {};
    if (!r.checked) {
      return `<div class="ct-cite-out bad"><p><strong>Not checked.</strong>
        ${esc(r.message || 'The appliance did not answer.')}</p>
        <p class="wm-hint">The counts above are still yours to type, and a certificate
        issued from them says so: nothing here has been verified against anything.</p></div>`;
    }
    const all = r.unverified === 0;
    const line = all
      ? `All ${r.total} citation${r.total === 1 ? '' : 's'} resolved to a real case.`
      : `${r.verified} of ${r.total} resolved to a real case. ${r.unverified} did not.`;
    return `<div class="ct-cite-out ${all ? 'ok' : 'warn'}">
      <p><strong>${esc(line)}</strong> Looked up against CourtListener
      ${r.cached ? '(from this page\u2019s cache of an identical passage)' : ''}.</p>
      <ul class="ct-cite-list">${(r.citations || []).map(citeRowHTML).join('')}</ul>
      <p class="wm-hint">Retrieval log digest
      <code class="ct-cite-digest">${esc(short(r.retrievalLogDigest || '', 12))}</code>
      \u2014 SHA-256 over the log above. That is what claim 3 now carries, instead of a
      digest of nothing.${all ? '' : ' A certificate issued from this passage records '
        + 'both true numbers, so a verifier checking that every citation was verified '
        + 'will fail claim 3. That is the honest answer and the demo does not hide it.'}</p>
      ${all ? '' : `<p class="ct-cite-todo"><strong>Remove the false citations before you issue.</strong>
      A certificate that still carries them will not verify. Press Use the corrected passage, or
      edit the passage and check it again.</p>`}
      ${r.corrected ? `<p><strong>Corrected passage:</strong> ${esc(r.corrected)}</p>` : ''}
      ${r.corrected ? `<div class="actions">
        <button type="button" class="btn ghost ct-citefix">Use the corrected passage</button></div>` : ''}
      </div>`;
  }

  // The call. Returns the server's own body whatever the status, because the server's
  // words are better than anything this page could invent \u2014 the 401 explains the
  // licence, the 502 explains that the check did not happen. A failure to reach it at
  // all is turned into the same fail-closed shape, so the caller has one thing to read.
  async function runCitationCheck(o) {
    const opts = o || {};
    const f = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!f) {
      return { checked: false, error: 'no_fetch',
        message: 'This page has no network access, so nothing could be checked.' };
    }
    const base = String(opts.base || CITE_BASE).replace(/\/+$/, '');
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (opts.key) headers.Authorization = 'Bearer ' + opts.key;
    let res;
    try {
      res = await f(base + '/v1/citations/check', {
        method: 'POST', headers: headers, cache: 'no-store',
        body: JSON.stringify(opts.citations ? { citations: opts.citations } : { text: opts.text || '' }),
      });
    } catch (err) {
      return { checked: false, error: 'unreachable',
        message: 'The appliance at ' + base + ' did not answer (' + err.message + '). '
          + 'Start the backend, or check the counts by hand and say so.' };
    }
    let body = null;
    try { body = await res.json(); } catch (err) { body = null; }
    if (!body || typeof body !== 'object') {
      return { checked: false, error: 'unreadable',
        message: 'The appliance answered HTTP ' + res.status + ' with something this page could not read.' };
    }
    return body.checked === true ? body : Object.assign({ checked: false }, body);
  }

  // ------------------------------------------------ asserted vs measured
  // backend/citations.py — asserted_block() and assertion_line(), same rules, same
  // words. Two numbers, not one: what the filer SAID beside what the check FOUND.
  //
  //   asserted 3,     measured 3/3  -> the work was done and it checks out
  //   asserted none,  measured 3/1  -> the pipeline caught bad cites before filing
  //   asserted 14/14, measured 3/1  -> somebody signed their name to a claim the record
  //                                    does not support. Mata v. Avianca, in two numbers.
  //
  // Both live inside the claim object, so the claims root covers both and the signature
  // covers the root. Edit either number afterwards and the certificate stops verifying.
  // The assertion is recorded and never trusted: nothing in verifyCertificate() reads it
  // to decide whether a claim passed.
  const ASSERTION_KEYS = ['citations', 'verified'];
  const ASSERTION_SOURCE = 'caller';

  // The number something is, or null if it is not one. Booleans are not numbers here:
  // reading `verified: true` as 1 would let it agree with one verified citation.
  function assertedNumber(v) {
    if (typeof v === 'boolean' || v === null || v === undefined) return null;
    const s = String(v).trim();
    if (s === '') return null;
    const n = Number(s);
    return isNaN(n) ? null : n;
  }

  // The caller's counts, verbatim, or null when they did not state any. Null is the
  // important half: no assertion means no `asserted` block on the certificate. Inventing
  // one — above all by copying the measured pair into it — would turn "the filer said
  // nothing" into "the filer agreed with us", which is not ours to write for them.
  function assertedBlock(sent, measured, source) {
    if (!sent || typeof sent !== 'object') return null;
    const m = measured || {};
    const block = {};
    let any = false;
    for (const k of ASSERTION_KEYS) {
      let v = sent[k];
      if (v === null || v === undefined || String(v).trim() === '') continue;
      // A form box hands over a string. The same box is recorded as a number everywhere
      // else on this certificate, so a numeric one is recorded as a number here too;
      // anything that is not a number is kept exactly as it was typed.
      const n = assertedNumber(v);
      block[k] = n === null ? String(v).trim() : n;
      any = true;
    }
    if (!any) return null;
    block.source = String(source || ASSERTION_SOURCE);
    // `agrees` answers for what the filer actually stated: someone who gave a citation
    // count and no verified count is answered on the count they gave.
    block.agrees = Object.keys(block).filter((k) => ASSERTION_KEYS.indexOf(k) >= 0)
      .every((k) => {
        const a = assertedNumber(block[k]), b = assertedNumber(m[k]);
        return a !== null && b !== null && a === b;
      });
    return block;
  }

  // The gap, on the page, the moment a lookup replaces what somebody typed. Shown
  // whether or not the two agree: "you said 3 and 1, the check found 3 and 1" is the
  // sentence that makes the other one believable.
  function assertedNoteHTML(block, measured) {
    if (!block) return '';
    const m = measured || {};
    const line = assertionLine({ citations: m.total, verified: m.verified, asserted: block });
    if (!line) {
      return `<div class="ct-assert agrees"><p><strong>Your numbers and the check agree.</strong>
        You stated ${esc(String(block.citations))} citations, ${esc(String(block.verified))} verified,
        and the check found the same. The certificate records both, and says they agree.</p></div>`;
    }
    return `<div class="ct-assert gap"><p><strong>Your numbers and the check do not agree.</strong>
      ${esc(line)}</p>
      <p class="wm-hint">Both go on the certificate, inside claim 3, covered by the signature.
      The check’s numbers are the ones claim 3 is proved against; yours are recorded as
      what you stated. Nothing here says which is right &mdash; a typo, a late edit and an
      invented citation all look the same from here.</p></div>`;
  }

  function assertedStated(block, key, noun, absent) {
    const v = block[key];
    return (v === null || v === undefined || v === '') ? absent : String(v) + ' ' + noun;
  }

  // The sentence a verdict carries when the two disagree, and '' when they do not.
  // Flat, and without adjectives: a typo, a late edit and a fabrication all look the
  // same from here, and which one it was is for a court to decide, not for this page.
  function assertionLine(evidence) {
    if (!evidence || typeof evidence !== 'object') return '';
    const block = evidence.asserted;
    if (!block || typeof block !== 'object' || block.agrees !== false) return '';
    return 'The filer stated '
      + assertedStated(block, 'citations', 'citations', 'no citation count stated') + ', '
      + assertedStated(block, 'verified', 'verified', 'no verified count stated')
      + '. The check found ' + evidence.citations + ' citations, ' + evidence.verified + ' verified.';
  }

  // ------------------------------------------------- the blank-field warning
  // Kevin's rule: sign with N/A on anything missing, but always say so first. So this is
  // a warning, not a block — it names every blank field by the label the form shows,
  // says what each one will be recorded as, and offers two plain choices. It is rebuilt
  // from the live form on every press: there is no "do not show again", because the
  // second certificate is exactly as permanent as the first.
  function listWords(a) {
    if (a.length <= 1) return a[0] || '';
    return a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1];
  }

  // One sentence per thing the blanks record as, each naming its own fields. "Some
  // fields are blank" tells the reader nothing; this always says which.
  function blankWarningSentences(blanks) {
    const groups = [];
    for (const b of blanks) {
      const g = groups.find((x) => x.records === b.records);
      if (g) g.labels.push(b.label); else groups.push({ records: b.records, labels: [b.label] });
    }
    return groups.map((g) => (g.records === NA
      ? `${listWords(g.labels)} will be recorded as N/A — not stated — inside the signature, `
        + 'where nobody can change it afterwards.'
      : `${listWords(g.labels)} will be recorded as ${g.records}.`));
  }

  function blankWarningHTML(blanks) {
    if (!blanks || !blanks.length) return '';
    const n = blanks.length;
    return `<div class="ct-warn" id="ct-warn" role="alertdialog" tabindex="-1"
      aria-labelledby="ct-warn-t" aria-describedby="ct-warn-d">
      <h4 id="ct-warn-t"><span class="ct-warn-mark" aria-hidden="true">!</span>
        ${n} field${n === 1 ? ' has' : 's have'} been left blank</h4>
      <p id="ct-warn-d">${blankWarningSentences(blanks).map(esc).join(' ')}</p>
      <ul class="ct-warn-list">${blanks.map((b) => `<li><span class="ct-warn-f">${esc(b.label)}</span>
        <span class="ct-warn-r">recorded as ${esc(b.records)}</span></li>`).join('')}</ul>
      <div class="actions">
        <button type="button" class="btn" id="ct-warn-back">Go back and fill them in</button>
        <button type="button" class="btn ghost" id="ct-warn-go">Issue anyway, recording N/A</button>
      </div>
      <p class="ct-warn-foot">Nothing has been signed yet.</p>
    </div>`;
  }

  // Fewer verified citations than citations means claim 3 fails, so the certificate will
  // not verify. Said before signing, with the fix one click away.
  function falseCiteWarningHTML(total, verified, fixable) {
    const bad = total - verified;
    return `<div class="ct-warn" id="ct-warn" role="alertdialog" tabindex="-1"
      aria-labelledby="ct-warn-t" aria-describedby="ct-warn-d">
      <h4 id="ct-warn-t"><span class="ct-warn-mark" aria-hidden="true">!</span>
        ${bad} citation${bad === 1 ? '' : 's'} did not check out</h4>
      <p id="ct-warn-d">Only ${verified} of ${total} citations were verified. A certificate issued now
      fails the citation check and will not verify. Remove the false citations first.</p>
      <div class="actions">
        ${fixable ? '<button type="button" class="btn" id="ct-warn-fix">Use the corrected passage and issue</button>' : ''}
        <button type="button" class="btn${fixable ? ' ghost' : ''}" id="ct-warn-back">Go back and fix them</button>
        <button type="button" class="btn ghost" id="ct-warn-go">Issue anyway</button>
      </div>
      <p class="ct-warn-foot">Nothing has been signed yet.</p>
    </div>`;
  }

  function certFormHTML(d) {
    const e = d.evidence;
    const O = CERT_OPTIONS;
    return `
    <div class="panel builder">
      <h3>Step 1 &mdash; Your Notarized Document</h3>
      <div class="field wm-field">
        ${ctLabel('ct-digest', 'Document digest (SHA-256, from the notarize step)', 'documentDigest')}
        <input id="ct-digest" class="wm-text mono" placeholder="64 hex characters">
        <p class="wm-hint">No digest yet? Notarize a document in the <a href="workplace.html#notarize">Workplace</a> first.</p>
      </div>

      <h3>Step 2 &mdash; Filing</h3>
      <div class="inline">
        ${ctField({ id: 'ct-court', label: 'Court', options: O.court, value: d.court })}
        ${ctField({ id: 'ct-judge', label: 'Judge', options: O.judge, value: d.judge })}
      </div>
      <div class="inline">
        ${ctText({ id: 'ct-case', label: 'Case number', value: d.caseNumber })}
        ${ctField({ id: 'ct-filing', label: 'Filing', options: O.filing, value: d.filing })}
        <div class="field wm-field">
          <span class="wm-labelrow"><label for="ct-firm-fixed">Firm (licensee)</label></span>
          <output class="wm-fixed" id="ct-firm-fixed">${esc(DEMO_FIRM)}</output>
        </div>
      </div>
      <h3 style="margin-top:18px">Step 3 &mdash; Model Manifest</h3>
      <div class="inline">
        ${ctField({ id: 'ct-model', label: 'Model', options: O.model,
          value: e['model-manifest'].model, help: 'model' })}
        <div class="field wm-field">
          ${ctLabel('ct-modelver', 'Version', 'version')}
          <input class="wm-text" id="ct-modelver" type="text" value="${esc(e['model-manifest'].version)}"
            placeholder="Type your own\u2026">
        </div>
        ${ctField({ id: 'ct-provider', label: 'Provider (optional)', options: O.provider,
          value: e['model-manifest'].provider, help: 'provider' })}
      </div>
      <h3 style="margin-top:18px">Step 4 &mdash; Attorney Adoption${ctHelp('attorneyFields')}</h3>
      <div class="inline">
        ${ctText({ id: 'ct-atty', label: 'Attorney', placeholder: EXAMPLES.attorney })}
        ${ctText({ id: 'ct-bar', label: 'Bar number', placeholder: EXAMPLES.barNumber })}
      </div>
      <div class="inline">
        ${ctField({ id: 'ct-juris', label: 'Jurisdiction (state)', options: O.jurisdiction,
          value: e['attorney-adoption'].jurisdiction })}
        ${ctText({ id: 'ct-court-specific', label: 'Specific court (optional)',
          placeholder: 'e.g. King County Superior Court', help: 'specificCourt' })}
      </div>
      <h3 style="margin-top:18px">Step 5 &mdash; Citations and Redaction</h3>
      <div class="inline">
        <div class="field wm-field"><span class="wm-labelrow"><label for="ct-cites">Citations in the filing</label></span>
          <input id="ct-cites" type="number" min="0" value="${e['citations-verified'].citations}"></div>
        <div class="field wm-field"><span class="wm-labelrow"><label for="ct-cverified">Independently verified</label></span>
          <input id="ct-cverified" type="number" min="0" value="${e['citations-verified'].verified}"></div>
        ${ctField({ id: 'ct-pipestep', label: 'Pipeline step', options: O.pipelineStep,
          value: e['citations-verified'].pipelineStep, help: 'pipelineStep' })}
      </div>
      <p class="wm-hint" id="ct-cite-manualnote">Typed by hand, those two numbers are an
      assertion: the certificate records them, and nothing has checked them. Below is the
      same claim, checked.</p>
      <div class="ct-cite" id="ct-cite">
        <span class="wm-labelrow"><label for="ct-citetext">Check the citations for real</label>${ctHelp('citationCheck')}</span>
        <textarea id="ct-citetext" class="ct-cite-text" rows="4"
          aria-describedby="ct-cite-privacy">${esc(CITE_EXAMPLE)}</textarea>
        <div class="inline">
          <div class="field wm-field"><span class="wm-labelrow"><label for="ct-citebase">Appliance API</label></span>
            <input id="ct-citebase" class="wm-text mono" type="text" value="${esc(CITE_BASE)}"></div>
          <div class="field wm-field"><span class="wm-labelrow"><label for="ct-citekey">Licence key</label></span>
            <input id="ct-citekey" class="wm-text mono" type="text" autocomplete="off"
              value="blf_lk_demo_bailment_law_free" placeholder="blf_lk_\u2026 \u2014 checking is a licensed call"></div>
        </div>
        <div class="actions">
          <button type="button" class="btn ghost" id="ct-citecheck">Check citations</button>
          <button type="button" class="btn ghost" id="ct-citereset">Restart citation check</button>
        </div>
        <p class="wm-hint" id="ct-cite-privacy">The passage is sent to your appliance, which sends it
        to CourtListener and to nowhere else. No model sees it, in this page or on the server.
        With no appliance running, nothing is sent anywhere and the two counts above stay yours
        to type.</p>
        <div id="ct-citeout" aria-live="polite"></div>
        <div id="ct-assertnote" aria-live="polite"></div>
      </div>
      <div class="inline">
        ${ctField({ id: 'ct-redactor', label: 'Redactor version', options: O.redactor,
          value: e['no-identifier'].redactorVersion, help: 'redactorVersion' })}
        <div class="field wm-field">
          ${ctLabel('ct-leaked', 'Identifiers that reached a model', 'identifiersReachedModel')}
          <input id="ct-leaked" type="number" min="0" value="${e['no-identifier'].identifiersReachedModel}">
        </div>
      </div>
      <div class="actions">
        <button class="btn" id="ct-issue">Issue &amp; sign certificate</button>
        <button class="btn ghost" id="ct-break">Tamper with it</button>
        <button class="btn ghost" id="ct-forge">Forge it properly (re-sign with a new key)</button>
        <button class="btn ghost" id="ct-print">Print</button>
      </div>
      <div id="ct-warn-slot"></div>
    </div>`;
  }


  // A field nobody answered must read as N/A and must LOOK different from one somebody
  // answered. A court should be able to tell at a glance what was not stated, so N/A is
  // marked wherever it appears and listed once at the top. Nothing is hidden: the mark is
  // a dotted underline in the certificate's own ink, so it survives printing in black.
  const isNA = (v) => String(v == null ? '' : v).trim() === NA;
  const naMark = (v) => (isNA(v) ? `<span class="cert-na" title="Not stated">${NA}</span>` : esc(v));

  // Every field on the issued certificate that came back N/A, named the way it is printed.
  function certNAFields(cert) {
    const out = [];
    const F = cert.filing || {};
    for (const [k, label] of [['court', 'court'], ['judge', 'judge'],
      ['caseNumber', 'case number'], ['title', 'filing title']]) {
      if (isNA(F[k])) out.push(label);
    }
    for (const c of cert.claims || []) {
      for (const [k, v] of Object.entries(c.evidence || {})) if (isNA(v)) out.push(k);
    }
    return out;
  }

  // The filer's own numbers, on the certificate a court reads, and never as one more
  // `key=value` in the run of evidence: a reader must not have to spot a disagreement by
  // comparing two numbers by eye. A gap gets its own block, its own rule down the side
  // and the flat sentence; an agreement is stated too, quietly, because an assertion
  // that was checked and held is worth as much as one that did not.
  function certAssertedHTML(evidence) {
    const block = evidence && typeof evidence === 'object' ? evidence.asserted : null;
    if (!block || typeof block !== 'object') return '';
    const line = assertionLine(evidence);
    if (!line) {
      return `<div class="cert-assert agrees"><span class="cert-assert-tag">stated and checked</span>
        The filer stated ${esc(assertedStated(block, 'citations', 'citations', 'no citation count'))},
        ${esc(assertedStated(block, 'verified', 'verified', 'no verified count'))}. The check found the
        same. Source: ${esc(String(block.source || ''))}.</div>`;
    }
    return `<div class="cert-assert gap"><span class="cert-assert-tag">stated ≠ checked</span>
      ${esc(line)} Source of the stated figures: ${esc(String(block.source || ''))}. Claim 3 above is
      proved against the numbers the check found.</div>`;
  }

  function certHTML(cert, url, fingerprint) {
    const na = certNAFields(cert);
    const naBanner = na.length ? `<p class="cert-na-banner"><strong>Not stated:</strong>
      ${esc(na.join(', '))}. ${na.length === 1 ? 'That field was' : 'Those fields were'}
      left blank and ${na.length === 1 ? 'is' : 'are'} recorded as
      <span class="cert-na">N/A</span>. Everything else below was answered.</p>` : '';
    return `
    <div class="cert" id="ct-doc">
      <div class="seal">
        <div>
          <h4>Certificate of AI-assisted preparation</h4>
          <div class="sub">${naMark(cert.filing.court)} &middot; ${naMark(cert.filing.judge)}
            &middot; No. ${naMark(cert.filing.caseNumber)}</div>
        </div>
        <div class="sub" style="text-align:right">Issued ${esc(fmtDate(cert.issued))}<br>
          ${esc(cert.issuer.name)}<br>${esc(cert.issuer.registryEntry)}</div>
      </div>
      <p style="color:var(--ink);font-size:.9rem">The undersigned service certifies the following about
        <strong>${naMark(cert.filing.title)}</strong>, prepared by ${esc(cert.license.firm)}, bearing the
        document digest below. The document itself is not disclosed by this certificate.</p>
      ${naBanner}
      ${cert.claims.map((c, i) => `
        <div class="claim">
          <div class="n">${i + 1}</div>
          <div>
            <div class="t">${esc(c.title)}</div>
            <div class="e">${esc(c.provedBy)}<br>
              ${Object.entries(c.evidence).filter(([k]) => k !== 'asserted')
                .map(([k, v]) => (isNA(v)
                  ? `<span class="cert-na" title="Not stated">${esc(k)}=${NA}</span>`
                  : `${esc(k)}=${esc(v)}`)).join(' &middot; ')}</div>
            ${certAssertedHTML(c.evidence)}
          </div>
        </div>`).join('')}
      <div class="foot">
        document digest &nbsp;${esc(cert.document.digest || '(not bound)')}<br>
        claims root &nbsp;${esc(cert.claimsRoot)}<br>
        signing key &nbsp;${esc(fingerprint)}<br>
        verify at &nbsp;${esc(short(url, 46))}
      </div>
    </div>
    ${monoBlock(url, 'Verification URL \u2014 hand this to the court, opposing counsel, anyone')}
    <p class="note">Anyone can check it: the URL carries the certificate and the signature, the verifier runs in
    their browser, and no Bailment software is involved. What the verifier does <em>not</em> take from the URL
    is the trust: it looks the signing key up in <code>registry.json</code>, which travels with the page. A
    certificate signed by a key that is not in that registry is reported as consistent but unregistered, never as
    a pass. Published, the same link reads <code>https://verify.bailment.tech/#c=\u2026</code>; here it stays
    relative so it opens straight off the disk. The signature is real; the registry is a demo registry holding
    demo keys; nothing is anchored to a chain yet.</p>`;
  }

  // One line per thing that was actually checked. `level` is always computed, never
  // written in by hand: a tick here means a comparison returned true.
  function certFindings(r) {
    const f = [];
    // Once the signature has failed, everything the certificate says is just text. Nothing
    // below may draw a tick on it. `lv` is the only place a tick is allowed to survive.
    const lv = (level) => (r.signature || level !== 'ok' ? level : 'warn');
    // A check that passed on a payload whose signature failed is not a result, it is a
    // property of unsigned text. Label it that way rather than letting it read as a tick.
    const lb = (label) => (r.signature ? label : 'Unsigned text only \u2014 ' + label);

    f.push(r.signature
      ? { level: 'ok', label: 'Signature valid',
          detail: `The certificate was signed by the key with fingerprint ${r.fingerprint}, and nothing in it has changed since.` }
      : { level: 'bad', label: 'Signature invalid',
          detail: 'The certificate does not match the signature it carries. Nothing it says was checked, '
            + 'and nothing below is evidence of anything.' });

    if (r.keyListed) {
      const s = r.registeredSigner;
      f.push(r.signature
        ? { level: 'ok', label: `Signing key is in the registry: ${s.firm}`,
            detail: `Key ${r.fingerprint} is listed as ${s.role}, valid ${fmtDate(s.window.from)} to `
              + `${fmtDate(s.window.until)}. Read from ${r.registrySource}.` }
        : { level: 'warn', label: `Key ${r.fingerprint} is listed in the registry, but it did not sign this`,
            detail: 'The key the certificate carries is a registered one, and the signature over the certificate '
              + 'still failed. Either the certificate was altered after signing, or the key was copied from '
              + 'somewhere it does belong. Nothing here was signed by its registered holder.' });
      if (r.signerNameMatch === false) {
        f.push({ level: 'bad', label: 'The certificate names a different issuer from the registry',
          detail: `The certificate says it was issued by "${r.issuerName}". The registry records this key to `
            + `"${s.name}". One of the two is wrong.` });
      }
    } else if (r.registeredSigner) {
      f.push({ level: 'bad', label: 'Signing key is in the registry, but not for this date',
        detail: `Key ${r.fingerprint} was valid ${fmtDate(r.registeredSigner.window.from)} to `
          + `${fmtDate(r.registeredSigner.window.until)}. This certificate is dated outside that window.` });
    } else {
      f.push({ level: 'warn', label: `Signed by key ${r.fingerprint}, which is not in the registry`,
        detail: 'That key came with the certificate, not from anywhere else. This page has no way to tell you '
          + 'whose key it is. Any firm, attorney or bar number below is text inside the file, not a fact checked here.' });
    }

    if (r.pipelineListed) {
      f.push({ level: lv('ok'), label: lb(`Pipeline version approved: ${r.pipeline.registryEntry}`),
        detail: `Approved on ${fmtDate(r.pipeline.approvedOn)} and not withdrawn.` });
    } else if (r.pipeline) {
      f.push({ level: 'warn', label: `Pipeline version withdrawn: ${r.pipeline.registryEntry}`,
        detail: `Withdrawn on ${fmtDate(r.pipeline.withdrawnOn)}. Work run under it is not covered.` });
    } else {
      f.push({ level: 'warn', label: `Pipeline version is not on the approved list: ${r.registryEntry}`,
        detail: 'That version string does not appear in the registry, so nothing is known about what produced '
          + 'the document.' });
    }

    f.push(r.licenseLive
      ? { level: lv('ok'), label: lb('The firm\u2019s licence was live when the certificate was issued'), detail: '' }
      : { level: 'bad', label: 'The firm\u2019s licence had already expired when the certificate was issued', detail: '' });
    if (r.licenseExpired && r.licenseLive) {
      f.push({ level: 'warn', label: 'That licence has since lapsed',
        detail: 'A lapsed licence does not void a certificate that was properly issued while it was live. It does '
          + 'mean the firm is not licensed today.' });
    }

    f.push(r.digestMatch === true
      ? { level: lv('ok'), label: lb('The filing in front of you is the document this certifies'), detail: '' }
      : r.digestMatch === false
        ? { level: 'bad', label: 'The filing in front of you is NOT the document this certifies', detail: '' }
        : { level: 'info', label: 'Not checked against your copy',
            detail: 'Paste the SHA-256 digest of the filing in front of you and this certificate will be bound to it. '
              + 'Until then, it could belong to a different document.' });

    if (r.caseMatch !== null) {
      f.push(r.caseMatch
        ? { level: lv('ok'), label: lb('Case number matches the one you entered'), detail: '' }
        : { level: 'bad', label: 'Case number does not match the one you entered', detail: '' });
    }

    f.push({ level: 'info', label: `Issued for: ${r.licenseeFirm}`,
      detail: 'The licensed firm is named by the issuer inside the signature. The registry lists signing keys and '
        + 'pipeline versions, not firms, so this page does not check that name against anything.' });
    return f;
  }

  const MARK = { ok: '\u2713', bad: '\u2717', warn: '!', info: '\u00b7' };

  function findingRows(findings) {
    return findings.map((f) => `
      <div class="kv"><span class="k ${f.level === 'info' ? 'muted' : esc(f.level)}">${MARK[f.level] || '\u00b7'}
        ${esc(f.label)}</span>
        <span class="v muted" style="white-space:pre-wrap">${esc(f.detail)}</span></div>`).join('');
  }

  function verdictHTML(r) {
    if (r.fatal) {
      return `<div class="verdict fail"><span class="mark">\u2717</span>
        <span><strong>Not readable</strong>${esc(r.fatal)}</span></div>`;
    }
    const findings = certFindings(r);

    const sub = r.state === 'pass'
      ? 'Signed by a key this registry names, under an approved pipeline version, with all four claims proved.'
      : r.state === 'open'
        ? (!r.registered
            ? 'Everything in this certificate agrees with itself and the signature checks out \u2014 but the key that '
              + 'signed it is not in the registry, so this page cannot tell you who signed it. Do not read it as proof '
              + 'that the named firm issued it.'
            : 'The signature and the claims check out, but the pipeline version named in this certificate is not on '
              + 'the approved list, so what produced the document is unknown.')
        : 'At least one check failed. The detail is below.';

    const table = r.signature
      ? `<table><thead><tr><th>Claim</th><th class="num">Inclusion</th><th class="num">Result</th></tr></thead>
         <tbody>${claimRows(r)}</tbody></table>
         <p class="note">Inclusion is a structural self-check: each claim is proved into the root the certificate
         carries. It shows the claims list was not edited after signing; it is not separate evidence.</p>`
      : `<div class="panel" style="border-style:dashed">
           <h3 class="bad">Unverified content \u2014 do not rely on any of it</h3>
           <p class="muted">The signature did not check out, so nothing below was signed by anyone. It is printed
           only so you can see what the file claims.</p>
           ${claimsQuarantineHTML(r)}
         </div>`;

    return `
      <div class="verdict ${r.state === 'pass' ? 'pass' : r.state === 'fail' ? 'fail' : 'open'}"
        ${r.state === 'open' ? 'style="border-color:color-mix(in srgb,var(--tint-ice) 55%,transparent)"' : ''}>
        <span class="mark">${r.state === 'pass' ? '\u2713' : r.state === 'fail' ? '\u2717' : '!'}</span>
        <span><strong>${esc(r.headline)}</strong>${esc(sub)}</span>
      </div>
      ${findingRows(findings)}
      ${table}`;
  }

  // A claim whose filer said one thing and whose check found another gets its own row
  // under it, flagged, in its own colour. A pass with a gap in it is still a pass — the
  // measured numbers decide that — but it must not read like a claim that simply
  // passed, and nobody should have to compare two numbers by eye to notice.
  function claimRows(r) {
    return r.claims.map((c, i) => `
      <tr${c.assertionNote ? ' class="claim-gap"' : ''}>
        <td>${i + 1}. ${esc(c.title)}
          ${c.assertionNote ? '<span class="claim-assert-tag">stated \u2260 checked</span>' : ''}
          <div class="${c.assertionNote ? 'claim-assert' : 'muted'}" style="font-size:.74rem">${
            esc(c.detail || c.provedBy)}</div></td>
        <td class="num">${c.included ? '<span class="ok">in root</span>' : '<span class="bad">not in root</span>'}</td>
        <td class="num">${c.ok ? '<span class="ok">\u2713 proved</span>'
          : `<span class="bad">\u2717 ${esc(c.missing.join(', '))}</span>`}</td>
      </tr>`).join('');
  }

  // Same claims, no ticks, no table chrome: unsigned text should not be able to borrow
  // the shape of a result.
  function claimsQuarantineHTML(r) {
    return r.claims.map((c, i) => `
      <p class="muted" style="font-size:.8rem;margin:.4rem 0">${i + 1}. ${esc(c.title)}
      &mdash; ${esc(c.detail || c.provedBy)}</p>`).join('');
  }

  function ctRender(el, mode) {
    // build   the generator, no verifier    (Certificate Generator, and the workplace dialog)
    // verify  the verifier, no generator    (Technology, Verify)
    // full    both, for anything that still asks for it
    const showBuilder = mode !== 'verify';
    const showVerifier = mode !== 'build';
    el.innerHTML = `
      <h2>A Certificate a Court Can Check</h2>
      ${showBuilder ? certFormHTML(CERT_DEFAULTS) : ''}
      <div id="ct-out"></div>
      ${showVerifier ? `
      <hr>
      <h3>Verifier</h3>
      <p>Paste a verification URL or payload. This runs entirely in your browser. The signing key is looked up
      in <code>registry.json</code>, which is part of this page and not part of the payload.</p>
      <div class="field"><textarea id="ct-payload" rows="3" placeholder="verify.html#c=\u2026"></textarea></div>
      <div class="inline">
        <div class="field"><label>Digest of the filing in front of me (optional, SHA-256)</label>
          <input id="ct-mydigest" class="mono" placeholder="64 hex characters"></div>
        ${ctText({ id: 'ct-mycase', label: 'Case number on the filing (optional)',
          placeholder: 'Leave blank and the case number is not checked' })}
      </div>
      <p class="note">Leave those blank and the certificate is still checked, but it is not tied to any
      particular document. Fill them in and a certificate lifted from another filing is caught.</p>
      <div class="actions"><button class="btn ghost" id="ct-verify">Verify</button></div>
      <div id="ct-result"></div>` : ''}`;

    wireCopy(el);
    wireFields(el);
    const out = $(el, '#ct-out');
    const result = $(el, '#ct-result');
    // The verifier is its own mount now, so a builder-only page has neither of these.
    const show = (html) => { if (result) result.innerHTML = html; };
    const setPayload = (v) => { const n = $(el, '#ct-payload'); if (n) n.value = v; };
    let last = null;
    let lastCheck = null;          // the last completed citation lookup, or null
    // What was in the two count boxes when that lookup replaced them. The filer's
    // assertion, kept so the certificate can record it beside the measurement.
    let typedCounts = { citations: '', verified: '' };

    // Which control answers which field. wmValue() reads a .wm-field: the chosen option,
    // or, when the option chosen is "Write my own", the text in the box beside it.
    const raw = (sel) => { const n = $(el, sel); return n ? n.value : ''; };
    const CONTROLS = {
      court: () => wmValue(el, 'ct-court'),
      judge: () => wmValue(el, 'ct-judge'),
      caseNumber: () => raw('#ct-case'),
      filing: () => wmValue(el, 'ct-filing'),
      documentDigest: () => raw('#ct-digest'),
      model: () => wmValue(el, 'ct-model'),
      version: () => raw('#ct-modelver'),
      provider: () => wmValue(el, 'ct-provider'),
      attorney: () => raw('#ct-atty'),
      barNumber: () => raw('#ct-bar'),
      jurisdiction: () => wmValue(el, 'ct-juris'),
      specificCourt: () => raw('#ct-court-specific'),
      citations: () => raw('#ct-cites'),
      verified: () => raw('#ct-cverified'),
      // Not a control. It is the digest of the retrieval log the last real check
      // produced, and it is empty until one has: the signer then falls back to the
      // demo's stand-in, which the form says out loud.
      retrievalLogDigest: () => (lastCheck && lastCheck.checked ? lastCheck.retrievalLogDigest : ''),
      // Also not controls. They hold what was typed into the two count boxes BEFORE a
      // real lookup overwrote them, so the certificate can record what the filer said
      // beside what the check found. Empty unless a lookup actually replaced something,
      // and cleared the moment the reader takes the counts back by hand: with no
      // measurement there is nothing for an assertion to differ from, and the typed
      // counts are already on the certificate as the filer's own numbers.
      assertedCitations: () => (lastCheck && lastCheck.checked ? typedCounts.citations : ''),
      assertedVerified: () => (lastCheck && lastCheck.checked ? typedCounts.verified : ''),
      pipelineStep: () => wmValue(el, 'ct-pipestep'),
      redactorVersion: () => wmValue(el, 'ct-redactor'),
      identifiersReachedModel: () => raw('#ct-leaked'),
    };
    const readForm = (name) => (CONTROLS[name] ? CONTROLS[name]() : '');
    const collect = () => certFieldsFrom(readForm);

    async function issue() {
      const keys = await demoSigningKeys();   // the registry's demo key, so the demo shows a real pass
      const cert = await buildCertificate(await collect());
      last = await signCertificate(cert, keys);
      const url = certificateURL(last);
      // The attorney's own record of what they signed, kept on their own device.
      if (root.Bailee && root.Bailee.profile) {
        root.Bailee.profile.record({
          kind: 'certification',
          title: (cert.filing && cert.filing.title) || 'Certificate',
          digest: (cert.document && cert.document.digest) || '',
          model: ((cert.claims || []).filter((c) => c.id === 'model-manifest')[0] || {}).evidence
            ? ((cert.claims || []).filter((c) => c.id === 'model-manifest')[0].evidence.model || '') : '',
          verifyUrl: url,
        });
      }
      out.innerHTML = certHTML(cert, url, await keyFingerprint(last.pub));
      setPayload(url);
      if (root.Bailee.ui.emit) root.Bailee.ui.emit('bailee:certified',
        { url: url, digest: (cert.document && cert.document.digest) || '' });
      wireCopy(out);
      show(verdictHTML(await verifyCertificate(last)));
    }

    if (showBuilder && root.Bailee && root.Bailee.profile) {
      // One identity. The attorney block comes from the profile rather than being retyped.
      root.Bailee.profile.load().then(() => { try { root.Bailee.profile.fillStep4(); } catch (e) { /* page has no builder */ } });
    }
    if (showBuilder) {
      // The version is not a question the reader should have to answer: picking a model
      // fills it in. A model the list does not carry — "In House Model", the two that do
      // not exist, or anything typed through "Write my own" — leaves the box empty,
      // because there is no build number we could honestly put there on their behalf.

      // Issue is gated on the warning, never blocked by it. Blanks are read off the live
      // form on every press, from the same CONTROLS the signer reads, so the list can
      // never name a field that is not about to be signed as N/A. No blanks, no warning:
      // the happy path is still one click.
      const slot = $(el, '#ct-warn-slot');
      const closeWarn = (focusId) => {
        slot.innerHTML = '';
        const back = focusId ? $(el, '#' + focusId) : null;
        if (back && back.focus) back.focus();
      };
      const issueRequested = async (citesChecked) => {
        const total = Number(cites.value) || 0, ok = Number(cverified.value) || 0;
        if (citesChecked !== true && total > ok) return citeGate(total, ok);
        const blanks = blankFields(readForm);
        if (!blanks.length) { slot.innerHTML = ''; return issue(); }
        slot.innerHTML = blankWarningHTML(blanks);
        const box = $(el, '#ct-warn');
        // "Go back" lands the reader on the first field the warning named, not at the
        // top of a form they now have to hunt through.
        $(el, '#ct-warn-back').addEventListener('click', () => closeWarn(blanks[0].id));
        $(el, '#ct-warn-go').addEventListener('click', async () => {
          slot.innerHTML = '';
          await issue();
        });
        box.addEventListener('keydown', (ev) => {
          if (ev.key === 'Escape') { ev.stopPropagation(); closeWarn(blanks[0].id); }
        });
        if (box.focus) box.focus();
        if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
      };
      const citeGate = (total, ok) => {
        const fixable = !!(lastCheck && lastCheck.corrected);
        slot.innerHTML = falseCiteWarningHTML(total, ok, fixable);
        const box = $(el, '#ct-warn');
        const toCite = () => {
          slot.innerHTML = '';
          const c = $(el, '#ct-cite');
          if (c && c.scrollIntoView) c.scrollIntoView({ block: 'start', behavior: 'smooth' });
        };
        $(el, '#ct-warn-back').addEventListener('click', toCite);
        $(el, '#ct-warn-go').addEventListener('click', () => { slot.innerHTML = ''; issueRequested(true); });
        if (fixable) {
          $(el, '#ct-warn-fix').addEventListener('click', async () => {
            slot.innerHTML = '';
            $(el, '#ct-citetext').value = lastCheck.corrected;
            await runCheck();
            issueRequested();
          });
        }
        box.addEventListener('keydown', (ev) => {
          if (ev.key === 'Escape') { ev.stopPropagation(); toCite(); }
        });
        if (box.focus) box.focus();
        if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
      };
      // --- claim 3, checked -------------------------------------------------
      // A real lookup owns the two counts afterwards: they are filled in from the
      // answer and locked, with a line saying where they came from. Locked is not a
      // trap \u2014 one button gives them back, and taking them back says plainly that
      // what is typed has not been checked.
      const cites = $(el, '#ct-cites'), cverified = $(el, '#ct-cverified');
      const manualNote = $(el, '#ct-cite-manualnote');
      const citeOut = $(el, '#ct-citeout');
      const assertNote = $(el, '#ct-assertnote');
      const lockCounts = (on) => {
        for (const box of [cites, cverified]) {
          box.readOnly = !!on;
          box.classList.toggle('ct-locked', !!on);
        }
        manualNote.textContent = on
          ? 'Those two numbers came from a real lookup, not from this form, so they are '
            + 'read-only. The certificate will carry them and the digest of the log they '
            + 'came from.'
          : 'Typed by hand, those two numbers are an assertion: the certificate records '
            + 'them, and nothing has checked them. Below is the same claim, checked.';
      };
      const startCounts = [cites.value, cverified.value];
      const resetCite = () => {
        $(el, '#ct-citetext').value = CITE_EXAMPLE;
        lastCheck = null;
        typedCounts = { citations: '', verified: '' };
        lockCounts(false);
        [cites.value, cverified.value] = startCounts;
        citeOut.innerHTML = '';
        assertNote.innerHTML = '';
      };
      $(el, '#ct-citereset').addEventListener('click', resetCite);
      const btn = $(el, '#ct-citecheck');
      async function runCheck() {
        btn.disabled = true;
        citeOut.innerHTML = '<p class="wm-hint">Looking every citation up\u2026</p>';
        let r = await runCitationCheck({
          base: raw('#ct-citebase'), key: raw('#ct-citekey'), text: raw('#ct-citetext'),
        });
        if (r.error === 'unreachable' || r.error === 'no_fetch') {
          r = (await demoCitationCheck(raw('#ct-citetext'))) || { checked: false, error: r.error,
            message: 'With no appliance running, this demo can only check its example passage. '
              + 'Press Restart citation check to put it back.' };
        }
        btn.disabled = false;
        citeOut.innerHTML = citeResultHTML(r);
        const fixBtn = citeOut.querySelector('button.ct-citefix');
        if (fixBtn) {
          fixBtn.addEventListener('click', () => {
            $(el, '#ct-citetext').value = r.corrected;
            runCheck();
          });
        }
        if (!r.checked) { lastCheck = null; lockCounts(false); return; }
        // Read the boxes BEFORE the answer overwrites them. Those two numbers are the
        // filer's assertion, and this is the last moment they exist.
        typedCounts = { citations: cites.value, verified: cverified.value };
        lastCheck = r;
        cites.value = String(r.total);
        cverified.value = String(r.verified);
        lockCounts(true);
        assertNote.innerHTML = assertedNoteHTML(assertedBlock(typedCounts,
          { citations: r.total, verified: r.verified }), r);
      }
      btn.addEventListener('click', runCheck);

      $(el, '#ct-issue').addEventListener('click', () => issueRequested());
      $(el, '#ct-print').addEventListener('click', () => window.print());
      $(el, '#ct-break').addEventListener('click', async () => {
        if (!last) { await issue(); }
        const broken = JSON.parse(JSON.stringify(last));
        broken.cert.claims[1].evidence.attorney = 'Someone Else, Esq.';
        setPayload(certificateURL(broken));
        show(verdictHTML(await verifyCertificate(broken, readerOpts()))
          + '<p class="note">One field changed after signing, and nothing re-signed. The signature fails and the '
          + 'claims root no longer matches. That is the easy case, and it is not the attack: a forger would simply '
          + 'sign their own text with their own key. Press <em>Forge it properly</em> to see that one.</p>');
      });

      // The real attack. Everything the old verifier checked still checks out; the only
      // thing that stops it is the registry.
      $(el, '#ct-forge').addEventListener('click', async () => {
        const forgerKeys = await generateSigningKey();
        const d = await collect();
        d.firm = 'Totally Not A Forgery LLP';
        d.evidence['attorney-adoption'].attorney = 'I. M. Fake';
        d.evidence['attorney-adoption'].barNumber = 'WSBA 00000';
        const forged = await signCertificate(await buildCertificate(d), forgerKeys);
        setPayload(certificateURL(forged));
        show(verdictHTML(await verifyCertificate(forged, readerOpts()))
          + '<p class="note">Nothing was tampered with. A new key was generated in this tab, a certificate naming '
          + 'a firm and an attorney that do not exist was signed with it, and every arithmetic check passes: the '
          + 'signature is valid, the claims root matches, all four claims prove in. The one thing that is not true '
          + 'is the one thing that matters, and the registry is what says so. That registry, not the cryptography, '
          + 'is where the defensibility is.</p>');
      });
    }

    const readerOpts = () => ({
      digest: $(el, '#ct-mydigest') ? $(el, '#ct-mydigest').value.trim() : '',
      caseNumber: $(el, '#ct-mycase') ? $(el, '#ct-mycase').value.trim() : '',
    });

    // Escape closes an explainer the keyboard opened. Hover closes itself.
    el.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Escape') return;
      const q = ev.target && ev.target.closest ? ev.target.closest('.wm-q') : null;
      if (q) q.blur();
    });

    if ($(el, '#ct-verify')) $(el, '#ct-verify').addEventListener('click', async () => {
      try {
        const p = decodePayload($(el, '#ct-payload').value);
        const r = await verifyCertificate(p, readerOpts());
        show(verdictHTML(r));
        if (root.Bailee.ui.emit) root.Bailee.ui.emit('bailee:verified', { ok: !!r.ok });
      } catch (err) {
        show(`<div class="verdict fail"><span class="mark">\u2717</span>
          <span><strong>Could not read that payload</strong>${esc(err.message)}</span></div>`);
      }
    });

    // verify.html#c=<payload>
    const fromHash = (typeof location !== 'undefined' && location.hash.startsWith('#c='))
      ? location.hash.slice(3) : null;
    if (fromHash) {
      setPayload(location.hash);
      (async () => {
        try { show(verdictHTML(await verifyCertificate(decodePayload(fromHash), readerOpts()))); }
        catch (err) {
          show(`<div class="verdict fail"><span class="mark">\u2717</span>
            <span><strong>Not readable</strong>That link does not carry a certificate this page can read.
            ${esc(err.message)}</span></div>`);
        }
      })();
    }
  }

  mount('certificate', ctRender);

  root.Bailee.certificate = { CERT_TYPE, VERIFY_BASE, CLAIM_SPEC, CERT_DEFAULTS, CERT_OPTIONS, MAX_CLAIMS, DEMO_SIGNER,
    DEMO_FIRM, NA, MODEL_VERSIONS, modelVersion, EXAMPLES, HELP,
    CITE_EXAMPLE, CITE_CORRECTED, demoCitationCheck, falseCiteWarningHTML, CITE_BASE, CITE_VERDICTS, COURTLISTENER,
    citeVerdict, citeRowHTML, citeResultHTML, runCitationCheck,
    ASSERTION_KEYS, ASSERTION_SOURCE, assertedBlock, assertionLine, assertedNoteHTML,
    certAssertedHTML, verdictHTML, claimRows,
    BLANKABLE, blankFields, blankWarningHTML, blankWarningSentences, certNAFields,
    demoSigningKeys, certificateShapeError, buildCertificate, signCertificate, encodePayload, decodePayload,
    certificateURL, verifyCertificate, certFindings, certFieldsFrom, certFormHTML, certHTML,
    ctField, ctText, ctHelp };
})(typeof globalThis !== 'undefined' ? globalThis : this);
