// The workplace console.  ->  Bailee.workplace   (load after crypto.js and ui.js)
//
// Two people in one thread with a model in it. The point of this screen is that the rules
// in section 7 of the plan are mechanisms, not manners:
//   R1  attribution lives in the data model  - no origin, no message, and nothing renders
//   R2  send is adoption                     - model output lands in the lawyer's pane, unsent
//   R3  there is no automated send path      - send needs an interactive lawyer session
//   R4  kind is set by the sender, default draft, never advice
//   R5  reference flows one way              - a tainted document cannot be notarized
//   R6  the client side may be live, the firm side is compose-then-send
//
// The screen speaks docs/workplace-api.md and nothing else. When no appliance answers it
// speaks to the stand-in in this file, which enforces the same rules and returns the same
// status codes, so the page still works when it is double-clicked. Offline is a mode, not
// the rules switched off.
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const CR = root.Bailee.crypto || {};
  const UI = root.Bailee.ui || {};
  const esc = UI.esc || ((s) => String(s == null ? '' : s));
  // Shared demo-input helpers (ui.js). Guarded because selfTest() and liveCheck() run in
  // node with no DOM and never render a field.
  const wmField = UI.wmField || function () { return ''; };
  const help = UI.help || function () { return ''; };
  const wmValue = UI.wmValue || function () { return ''; };
  const wmReset = UI.wmReset || function () {};
  const wireFields = UI.wireFields || function () {};

  // Demo choices. Nothing arrives pre-typed: every list below is a dropdown ending in
  // "Write my own", and clicking the box is the same thing.
  const MATTER_TITLES = ['Supply Co. Lawsuit'];
  const CLIENT_NAMES = ['John Client'];
  const LAWYER_NAMES = ['Kevin G. Mohr, Esq.'];
  // The client's box starts empty: whatever they want to say, in their own words. The
  // opening line below is the thread the demo starts from, not a suggestion in the box.
  const CLIENT_LINES = [''];
  const OPENING_MESSAGE = 'They stopped shipping on the 9th and stopped answering. Do we have a claim?';
  const LAWYER_LINES = [
    'On the facts as you have given them there is a claim in contract. Here is what I need next.',
    'Hold off on contacting them directly until we have the whole file.',
    'Draft demand letter follows for your comments. Do not send anything yourself.',
  ];
  // The free public demo licence. Seeded by backend/seed.py, long-lived and generously
  // funded, and printed here on purpose.
  const DEMO_LICENCE = 'blf_lk_demo_bailment_law_free';

  const OUTCOMES = ['Settled. Paid in full.', 'Dismissed with prejudice.',
    'Withdrawn by the client.'];

  /* --------------------------------------------------------------- shared */

  const ORIGINS = ['human', 'model'];
  const KINDS = ['draft', 'tool_output', 'advice'];
  const KIND_LABEL = { draft: 'draft', tool_output: 'tool output', advice: 'advice' };

  // The appliance is the only inference endpoint in a licensed configuration, pinned by a
  // signed model manifest (rule 1 in the plan). The stand-in says which model it pretends
  // to be for the same reason the real one must: a message that cannot say where it came
  // from is not storable.
  // What the compose bar offers. The appliance is the only one that actually runs today;
  // the rest are here so the switch is visible, and the log records what was asked for.
  const MODELS = [
    ['appliance/llama-3.1-70b-instruct@2026.9.3', 'Llama 3.1 70B \u2014 firm appliance'],
    ['appliance/qwen-2.5-72b-instruct@2026.8.1', 'Qwen 2.5 72B \u2014 firm appliance'],
    ['appliance/mistral-large@2026.7.2', 'Mistral Large \u2014 firm appliance'],
  ];
  const HARNESSES = [
    ['drafting', 'Drafting'],
    ['citation-check', 'Citation check'],
    ['redacted', 'Redacted research'],
  ];

  const MODEL = {
    id: 'appliance/llama-3.1-70b-instruct@2026.9.3',
    manifest: 'bailee-pipeline/2026.9.3',
  };

  const STAGES = [
    ['opened', 'Opened', 'the matter exists'],
    ['client_enrolled', 'Client enrolled', 'the client used their one-time link'],
    ['documents_in', 'Documents in', 'a first document was registered'],
    ['work_in_progress', 'Work in progress', 'the lawyer sent a message'],
    ['notarized', 'Notarized', 'a Document Record entry exists'],
    ['filed', 'Filed', 'a certificate was issued against this matter'],
    ['closed', 'Closed', 'closed with an outcome'],
  ];

  // Errors carry the status the contract names, because the status is the demonstration.
  function fail(status, message, extra) {
    const e = new Error(message);
    e.status = status;
    if (extra) Object.assign(e, extra);
    return e;
  }

  const nowISO = () => new Date().toISOString();
  const isHex64 = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s);

  /* ------------------------------------------------ the offline stand-in */
  // Same endpoints, same rules, same refusals, no server. Everything a caller gets back
  // is built here from the same code path the seeded demo used, so the seed cannot cheat.
  function createLocalApi(opts) {
    const o = opts || {};
    const db = { matters: {}, seq: 0, enrolments: {} };
    const nextId = (p) => p + (++db.seq);

    const FIRM_KEY = o.firmKey || 'firm_2a9f_cranmer_vale';
    const LAWYER_NAME = o.lawyerName || 'Kevin G. Mohr, Esq.';

    function matterOr404(id) {
      const m = db.matters[id];
      // Never leak one matter's existence to the other party: 404 and 403 read alike.
      if (!m) throw fail(404, 'No such matter.');
      return m;
    }

    // Who is calling, and may they. A service key is not a party to anything.
    function partyOf(m, auth) {
      if (!auth || !auth.key) throw fail(401, 'No key.');
      if (auth.role === 'client') {
        if (auth.key !== m.clientToken) throw fail(403, 'Not a party to this matter.');
        return 'client';
      }
      if (auth.role === 'lawyer' || auth.role === 'firm') {
        if (auth.key !== m.firmKey) throw fail(403, 'Not a party to this matter.');
        return auth.role;
      }
      throw fail(403, 'Not a party to this matter.');
    }

    function event(m, stage, note) {
      if (m.stages[stage]) return;
      m.stages[stage] = { at: nowISO(), note: note || '' };
    }

    function progressOf(m) {
      let next = null;
      const stages = STAGES.map(function (s) {
        const done = m.stages[s[0]] || null;
        if (!done && !next) next = s[0];
        return { id: s[0], label: s[1], why: s[2], done: !!done, at: done ? done.at : null, note: done ? done.note : '' };
      });
      return { matterId: m.id, stages: stages, next: next };
    }

    function visible(m, who) {
      // The client is never handed an unsent draft. Not hidden in the view: never sent.
      return m.messages.filter((x) => (who === 'client' ? (x.side === 'client' || x.sent) : true));
    }

    async function createMatter(auth, body) {
      if (!auth || auth.key !== FIRM_KEY) throw fail(403, 'A firm key opens a matter.');
      const id = nextId('mat_');
      const m = {
        id: id,
        title: (body && body.title) || 'Untitled matter',
        clientName: (body && body.clientName) || 'The client',
        lawyerName: LAWYER_NAME,
        firmKey: FIRM_KEY,
        enrolToken: nextId('enrol_'),
        clientToken: null,
        openedAt: nowISO(),
        messages: [], documents: [], adoptions: [], certificates: [],
        outcome: null, stages: {},
      };
      event(m, 'opened', 'the firm opened the matter');
      db.matters[id] = m;
      return { matterId: id, clientEnrolUrl: 'workplace.html#enrol=' + m.enrolToken };
    }

    async function listMatters(auth) {
      if (!auth || auth.key !== FIRM_KEY) throw fail(403, 'A firm key lists matters.');
      return { matters: Object.keys(db.matters).map((k) => ({
        matterId: k, title: db.matters[k].title, clientName: db.matters[k].clientName,
        progress: progressOf(db.matters[k]),
      })) };
    }

    async function getMatter(auth, id) {
      const m = matterOr404(id);
      const who = partyOf(m, auth);
      return {
        matterId: m.id, title: m.title, clientName: m.clientName, lawyerName: m.lawyerName,
        openedAt: m.openedAt, you: who, outcome: m.outcome,
        participants: [
          { role: 'lawyer', name: m.lawyerName, key: UI.short ? UI.short(m.firmKey, 6) : m.firmKey },
          { role: 'client', name: m.clientName, enrolled: !!m.clientToken },
        ],
        progress: progressOf(m),
      };
    }

    // One-time token in, participant token out. First use is the enrolment event.
    async function enrol(id, token) {
      const m = matterOr404(id);
      if (!token || token !== m.enrolToken) throw fail(403, 'That link is not for this matter.');
      if (!m.clientToken) {
        m.clientToken = nextId('part_');
        event(m, 'client_enrolled', 'the client used the one-time link');
      }
      return { matterId: m.id, participantToken: m.clientToken, role: 'client', name: m.clientName };
    }

    async function thread(auth, id) {
      const m = matterOr404(id);
      const who = partyOf(m, auth);
      return { matterId: m.id, you: who, messages: visible(m, who).map((x) => Object.assign({}, x)) };
    }

    async function postMessage(auth, id, body) {
      const m = matterOr404(id);
      const who = partyOf(m, auth);
      const b = body || {};
      // R1. origin is NOT NULL with no default. A message that cannot say where it came
      // from is refused here, before it exists, not filtered later.
      if (ORIGINS.indexOf(b.origin) < 0) {
        throw fail(400, 'origin is required and has no default. Say human or model.');
      }
      // R4. The sender sets kind. Absent, it is a draft. It is never advice by default.
      const kind = b.kind == null || b.kind === '' ? 'draft' : b.kind;
      if (KINDS.indexOf(kind) < 0) throw fail(400, 'kind must be draft, tool_output or advice.');
      if (b.origin === 'model' && !b.modelId) throw fail(400, 'A model message must name the model.');
      const text = String(b.body == null ? '' : b.body).trim();
      if (!text) throw fail(400, 'An empty message is not a message.');

      const side = who === 'client' ? 'client' : 'lawyer';
      // The client's link is a VPN. A client session that says it is disconnected cannot send.
      if (side === 'client' && auth && auth.vpn === false) {
        throw fail(403, 'The client VPN is not connected. Connect it, then send.');
      }
      // R2 and R6. The firm side is compose-then-send; the client side is live.
      const live = side === 'client';
      const msg = {
        id: nextId('msg_'), at: nowISO(), side: side,
        author: side === 'client' ? m.clientName : m.lawyerName,
        authorKey: auth.key,
        origin: b.origin,
        modelId: b.origin === 'model' ? String(b.modelId) : null,
        kind: kind,
        body: text,
        sent: live, sentAt: live ? nowISO() : null, sentBy: live ? auth.key : null,
        taint: true,   // everything in a privileged thread is privileged
      };
      m.messages.push(msg);
      return Object.assign({}, msg);
    }

    // R3. Interactive lawyer session or nothing. No service route exists to this function.
    async function send(auth, id, body) {
      const m = matterOr404(id);
      if (!auth || auth.role !== 'lawyer') {
        throw fail(403, 'Send is lawyer only. A service key or a partner key cannot send.');
      }
      if (auth.interactive !== true) {
        throw fail(403, 'Send needs an interactive lawyer session. There is no automated send path.');
      }
      partyOf(m, auth);
      const msg = m.messages.filter((x) => x.id === (body && body.messageId))[0];
      if (!msg) throw fail(404, 'No such message.');
      if (msg.side !== 'lawyer') throw fail(403, 'That message is not yours to send.');
      if (msg.sent) throw fail(409, 'That message was already sent. Adoption happens once.');
      const kind = body.kind == null || body.kind === '' ? 'draft' : body.kind;
      if (KINDS.indexOf(kind) < 0) throw fail(400, 'kind must be draft, tool_output or advice.');
      msg.kind = kind;
      msg.sent = true;
      msg.sentAt = nowISO();
      msg.sentBy = auth.key;
      m.adoptions.push({ messageId: msg.id, key: auth.key, at: msg.sentAt, kind: kind });
      event(m, 'work_in_progress', 'the lawyer sent a message');
      return Object.assign({}, msg);
    }

    // Output lands in the caller's own pane. For the lawyer that means an unsent draft.
    async function assist(auth, id, body) {
      const m = matterOr404(id);
      const who = partyOf(m, auth);
      const prompt = String((body && body.prompt) || '').trim();
      return postMessage(auth, id, {
        body: stubModel(who, prompt, m),
        origin: 'model',
        modelId: MODEL.id,
        kind: 'draft',
      });
    }

    async function addDocument(auth, id, body) {
      const m = matterOr404(id);
      partyOf(m, auth);
      const b = body || {};
      if (!b.filename) throw fail(400, 'A document needs a filename.');
      if (!isHex64(b.digest)) throw fail(400, 'digest must be a SHA-256 in hex.');
      // R5. Taint is carried, not asked about. Anything derived from the thread arrives set.
      const doc = {
        id: nextId('doc_'), filename: String(b.filename), digest: String(b.digest).toLowerCase(),
        taint: !!b.taint, taintPath: b.taint ? String(b.taintPath || 'derived from the privileged thread') : null,
        addedAt: nowISO(), addedBy: auth.role, notarized: null,
      };
      m.documents.push(doc);
      event(m, 'documents_in', doc.filename + ' was registered');
      return Object.assign({}, doc);
    }

    async function notarize(auth, id, body) {
      const m = matterOr404(id);
      partyOf(m, auth);
      const doc = m.documents.filter((x) => x.id === (body && body.documentId))[0];
      if (!doc) throw fail(404, 'No such document.');
      // R5 again, and this is the one that matters: refused outright, with the path shown.
      if (doc.taint) {
        throw fail(409, 'Notarize refused. This document came out of the privileged thread.',
          { taintPath: doc.taintPath, documentId: doc.id });
      }
      if (doc.notarized) return Object.assign({}, doc);
      const nonce = CR.randomNonce ? CR.randomNonce(32) : new Uint8Array(32);
      // The real appliance commits to the digest the same way document_record.compact does.
      const commitment = CR.commit ? CR.hex(await CR.commit(CR.unhex(doc.digest), nonce)) : doc.digest;
      doc.notarized = { commitment: commitment, nonce: CR.hex ? CR.hex(nonce) : '', at: nowISO(), by: auth.role };
      event(m, 'notarized', doc.filename + ' has a Document Record entry');
      return Object.assign({}, doc);
    }


    // The chain of custody, in the stand-in. Same shape as the appliance: the message is
    // redacted HERE, the digest covers the record rather than the sentence, and the
    // document that comes out is clean because this code did the redacting.
    const REDACTOR = 'bailee-redactor@2026.9.3';
    function redactRecord(m, msg) {
      const out = [];
      let text = String(msg.body || '');
      const lit = [['[CLIENT]', m.clientName], ['[MATTER]', m.title]];
      (m.participants || []).forEach(function (p) { lit.push(['[PERSON]', p]); });
      lit.forEach(function (pair) {
        const v = String(pair[1] || '').trim();
        if (!v) return;
        const rx = new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'ig');
        const hits = text.match(rx);
        if (hits) { out.push({ what: pair[0], count: hits.length }); text = text.replace(rx, pair[0]); }
      });
      [['[CASE-NO]', /\b\d{1,2}:\d{2}-[a-z]{2}-\d{3,6}\b/ig],
       ['[EMAIL]', /[\w.+-]+@[\w-]+\.[\w.]{2,}/ig],
       ['[PHONE]', /\+?\d[\d ().-]{8,}\d/ig]].forEach(function (pair) {
        const hits = text.match(pair[1]);
        if (hits) { out.push({ what: pair[0], count: hits.length }); text = text.replace(pair[1], pair[0]); }
      });
      return { redactedBody: text, removed: out,
        identifiersRemoved: out.reduce(function (a, r) { return a + r.count; }, 0) };
    }

    async function notarizeMessage(auth, id, messageId) {
      const m = matterOr404(id);
      const who = partyOf(m, auth);
      const msg = m.messages.filter((x) => x.id === messageId)[0];
      if (!msg) throw fail(404, 'No such message.');
      if (who === 'client' && msg.side === 'lawyer' && !msg.sent) {
        throw fail(403, 'That message was never sent to you, so it is not yours to notarise.');
      }
      const red = redactRecord(m, msg);
      const record = {
        type: 'bailment.ai/thread-record/v1', messageId: msg.id, matterId: m.id,
        side: msg.side, origin: msg.origin, kind: msg.kind, modelId: msg.modelId || null,
        createdAt: msg.at, sentAt: msg.sentAt || null,
        redactedBody: red.redactedBody, redactor: REDACTOR,
        identifiersRemoved: red.identifiersRemoved,
      };
      const digest = CR.hex(await CR.sha256(JSON.stringify(record)));
      const doc = {
        id: nextId('doc_'), filename: 'thread-record-' + msg.id + '.json', digest: digest,
        taint: false,
        taintPath: [msg.id + ': redacted in the appliance by ' + REDACTOR + ', '
          + red.identifiersRemoved + ' identifier(s) removed. The thread text did not move.'],
        derivedFrom: [msg.id], at: nowISO(), addedBy: auth.role, notarized: null,
      };
      m.documents.push(doc);
      const out = await notarize(auth, id, { documentId: doc.id });
      // Same shape the appliance answers with, so the page has one code path.
      return { record: { commitment: (out.notarized || {}).commitment || '',
                         at: (out.notarized || {}).at || nowISO(), derivedFrom: [msg.id] },
               document: { documentId: out.id, filename: out.filename, digest: out.digest },
               redaction: red };
    }

    // Notarize Chat: every SENT message, redacted here, in one record. Sent only, so both
    // sides commit to the conversation they both saw, never to an unsent draft.
    async function notarizeThread(auth, id) {
      const m = matterOr404(id);
      partyOf(m, auth);
      const sent = m.messages.filter((x) => x.sent);
      if (!sent.length) throw fail(400, 'Nothing has been sent in this chat yet, so there is nothing to notarise.');
      let removed = 0;
      const entries = sent.map(function (msg) {
        const red = redactRecord(m, msg);
        removed += red.identifiersRemoved;
        return { messageId: msg.id, side: msg.side, origin: msg.origin, kind: msg.kind,
          modelId: msg.modelId || null, createdAt: msg.at, sentAt: msg.sentAt || null,
          redactedBody: red.redactedBody };
      });
      const record = { type: 'bailment.ai/chat-record/v1', matterId: m.id, messages: entries,
        messageCount: entries.length, redactor: REDACTOR, identifiersRemoved: removed };
      const ids = entries.map((e) => e.messageId);
      const n = m.documents.filter((d) => /^chat-record-/.test(d.filename)).length + 1;
      const doc = {
        id: nextId('doc_'), filename: 'chat-record-' + m.id + '-' + n + '.json',
        digest: CR.hex(await CR.sha256(JSON.stringify(record))), taint: false,
        taintPath: [entries.length + ' sent message(s) redacted in the appliance by ' + REDACTOR
          + ', ' + removed + ' identifier(s) removed. The thread text did not move.'],
        derivedFrom: ids, at: nowISO(), addedBy: auth.role, notarized: null,
      };
      m.documents.push(doc);
      const out = await notarize(auth, id, { documentId: doc.id });
      return { record: { commitment: (out.notarized || {}).commitment || '',
                         at: (out.notarized || {}).at || nowISO(), derivedFrom: ids },
               document: { documentId: out.id, filename: out.filename, digest: out.digest },
               redaction: { identifiersRemoved: removed, messageCount: entries.length,
                            redactedBody: entries.map((e) => e.redactedBody).join('\n') } };
    }

    async function progress(auth, id) {
      const m = matterOr404(id);
      partyOf(m, auth);
      return progressOf(m);
    }

    /* -- beyond v1 of the contract. The stand-in can close the rail; a live appliance
          has no endpoint for these yet, so the buttons are hidden in live mode. -- */
    async function issueCertificate(auth, id, body) {
      const m = matterOr404(id);
      partyOf(m, auth);
      const doc = m.documents.filter((x) => x.id === (body && body.documentId))[0];
      if (!doc) throw fail(404, 'No such document.');
      if (!doc.notarized) throw fail(409, 'A certificate is issued against a notarized document.');
      const cert = { id: nextId('cert_'), documentId: doc.id, at: nowISO(),
        digest: doc.notarized.commitment.slice(0, 32) };
      m.certificates.push(cert);
      event(m, 'filed', 'a certificate was issued against ' + doc.filename);
      return cert;
    }

    async function close(auth, id, body) {
      const m = matterOr404(id);
      partyOf(m, auth);
      const outcome = String((body && body.outcome) || '').trim();
      if (!outcome) throw fail(400, 'A matter closes with an outcome, not with a button.');
      m.outcome = outcome;
      event(m, 'closed', outcome);
      return { matterId: m.id, outcome: outcome };
    }

    return {
      mode: 'offline', label: 'offline stand-in', firmKey: FIRM_KEY, extras: true,
      createMatter, listMatters, getMatter, enrol, thread, postMessage, send, assist,
      addDocument, notarize, notarizeMessage, notarizeThread, progress, issueCertificate, close,
    };
  }

  // A stub model. It is stubbed; it is still attributed, which is the part that matters.
  function stubModel(who, prompt, m) {
    const subject = prompt || (m.messages.filter((x) => x.origin === 'human').slice(-1)[0] || {}).body || m.title;
    if (who === 'client') {
      return 'Working note. You asked about: "' + trim(subject, 90) + '". '
        + 'Points to raise with your lawyer: the date shipments stopped, the notice clause, '
        + 'and what you did to cover. This is your own note. It is not advice.';
    }
    return 'Draft reply. Re: "' + trim(subject, 90) + '". '
      + 'On these facts a claim for breach looks arguable: performance stopped on a fixed date, '
      + 'notice was given, and cover costs are documented. Next step is the contract itself, '
      + 'clause 11. Cite nothing from this draft until the citations are checked.';
  }

  const trim = (s, n) => (String(s || '').length > n ? String(s).slice(0, n) + '\u2026' : String(s || ''));

  /* ------------------------------------------------------- the real thing */
  // docs/workplace-api.md as the appliance actually built it, which is the contract plus
  // eight additive things (backend/WORKPLACELOG.md). Nothing clever: a bearer key, JSON
  // in, JSON out, and the status code handed straight back to the screen.
  //
  // The live API answers in its own shape — `side: 'firm'`, `createdAt`, an envelope round
  // every answer — and the screen was written against the stand-in's shape. Translating
  // at this boundary, once, is better than teaching every renderer two shapes: the stand-in
  // stays the definition of what the page draws, and this is the adapter.

  const STAGE_LABEL = {};
  const STAGE_WHY = {};
  STAGES.forEach(function (s) { STAGE_LABEL[s[0]] = s[1]; STAGE_WHY[s[0]] = s[2]; });

  function liveMessage(m) {
    if (!m) return m;
    return {
      id: m.id, at: m.createdAt || m.sentAt,
      // the API calls the firm's side 'firm'; this screen has always called it the lawyer
      side: m.side === 'client' ? 'client' : 'lawyer',
      author: m.author, origin: m.origin, modelId: m.modelId, kind: m.kind, body: m.body,
      sent: !!m.sent, sentAt: m.sentAt, sentBy: m.sentBy,
      taint: m.privilegedTaint !== false,
      adoption: m.adoption || null,
    };
  }

  function liveDocument(d) {
    if (!d) return d;
    const path = Array.isArray(d.taintPath) ? d.taintPath.join(' \u2192 ') : (d.taintPath || '');
    return {
      id: d.documentId, filename: d.filename, digest: d.digest,
      taint: !!d.taint, taintPath: d.taint ? (path || 'derived from the privileged thread') : null,
      addedAt: d.createdAt, addedBy: d.addedBy || d.side,
      notarized: d.notarizedAt
        ? { commitment: d.commitment || '', nonce: d.nonce || '', at: d.notarizedAt, by: d.addedBy }
        : null,
    };
  }

  // The live progress answer names each stage and the EVENT that completed it. The rail
  // wants an id, a label and a reason, so the reason it shows for a finished stage is the
  // evidence the API recorded, not a sentence written in this file.
  function liveProgress(p) {
    if (!p || !p.stages) return p;
    return {
      matterId: p.matterId,
      next: p.next,
      stages: p.stages.map(function (s) {
        return {
          id: s.stage, label: STAGE_LABEL[s.stage] || s.stage, why: STAGE_WHY[s.stage] || s.event,
          done: !!s.done, at: s.at, note: s.evidence || s.event || '',
        };
      }),
    };
  }

  function createRemoteApi(base) {
    const origin = String(base || '').replace(/\/+$/, '');
    // A path that already starts at /v1 is somewhere else in the same API — the
    // certificate endpoint lives in app.py, not under the workplace prefix.
    const url = (p) => origin + (p.indexOf('/v1/') === 0 ? p : '/v1/workplace' + p);

    async function call(auth, method, path, body) {
      if (typeof fetch !== 'function') throw fail(0, 'This runtime has no fetch.');
      const headers = { Accept: 'application/json' };
      if (auth && auth.key) headers.Authorization = 'Bearer ' + auth.key;
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      let res;
      try {
        res = await fetch(url(path), {
          method: method, headers: headers, cache: 'no-store',
          body: body === undefined ? undefined : JSON.stringify(body),
        });
      } catch (e) { throw fail(0, 'The appliance did not answer: ' + e.message); }
      const text = await res.text();
      let data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = { message: text }; }
      if (!res.ok) {
        const msg = (data && (data.message || data.detail || data.error)) || ('HTTP ' + res.status);
        throw fail(res.status, String(msg), data && typeof data === 'object' ? data : null);
      }
      return data;
    }

    async function notarize(auth, id, body) {
      const r = await call(auth, 'POST', '/matters/' + id + '/notarize', body);
      // The answer is split: the Document Record entry, and the document it was made
      // from. The screen wants one document with a commitment on it.
      const doc = liveDocument(Object.assign({}, r.document,
        { commitment: (r.record || {}).commitment, nonce: r.nonce }));
      doc.charged = r.charged || null;
      return doc;
    }

    // `filed` completes when a certificate is issued AGAINST THIS MATTER. That endpoint is
    // the licensed one in app.py, it takes the firm's licence key, and it wants the four
    // claims with their evidence. Two of those four are the console's own facts: the model
    // this thread was actually served by, and the adoption record the appliance handed
    // back when the lawyer sent. The other two are demonstration values and the page says so.
    async function issueCertificate(auth, id, body) {
      const b = body || {};
      const doc = b.document || {};
      const adoption = b.adoption || {};
      const r = await call(auth, 'POST', '/v1/certificates', {
        matterId: id,
        court: b.court || 'Superior Court of Washington, King County',
        judge: b.judge || 'Hon. A. Example',
        caseNumber: b.caseNumber || 'demo-' + String(id).slice(-6),
        filing: doc.filename || 'Document Record entry',
        documentDigest: doc.digest || '',
        evidence: {
          'model-manifest': {
            model: b.modelId || MODEL.id, version: MODEL.manifest,
            provider: 'the firm\u2019s own appliance',
            manifestDigest: b.manifestDigest || '0'.repeat(64),
          },
          'attorney-adoption': {
            attorney: adoption.sentBy || b.lawyerName || 'the lawyer on this matter',
            barNumber: b.barNumber || 'DEMO 00000',
            jurisdiction: b.jurisdiction || 'Washington',
            // real: the appliance computed this when the draft was adopted
            sendRecordDigest: adoption.sendRecordDigest || '0'.repeat(64),
            adoptedAt: adoption.sentAt || new Date().toISOString(),
          },
          'citations-verified': {
            citations: 0, verified: 0, retrievalLogDigest: '0'.repeat(64),
            pipelineStep: MODEL.manifest,
          },
          'no-identifier': {
            redactorVersion: 'demonstration', templateVaultSplit: true,
            identifiersReachedModel: 0,
          },
        },
      });
      return { id: r.claimsRoot, at: r.issued, url: r.url, documentId: doc.id,
               demo: !adoption.sendRecordDigest };
    }

    return {
      mode: 'live', label: 'live appliance', base: origin,
      // Both of these exist now: POST /close, and POST /v1/certificates {matterId}.
      extras: true,
      createMatter: (auth, b) => call(auth, 'POST', '/matters', b),
      listMatters: (auth) => call(auth, 'GET', '/matters'),
      getMatter: (auth, id) => call(auth, 'GET', '/matters/' + id),
      // NO bearer key: the one-time token is the credential. A client never has a licence.
      enrol: (id, token, displayName) => call(null, 'POST', '/matters/' + id + '/enrol',
        { token: token, displayName: displayName || '' }),
      thread: async function (auth, id) {
        const r = await call(auth, 'GET', '/matters/' + id + '/thread');
        return Object.assign({}, r, { messages: (r.messages || []).map(liveMessage) });
      },
      postMessage: async (auth, id, b) =>
        liveMessage((await call(auth, 'POST', '/matters/' + id + '/messages', b)).message),
      send: async function (auth, id, b) {
        const r = await call(auth, 'POST', '/matters/' + id + '/send', b);
        return Object.assign(liveMessage(r.message), { adoption: r.adoption || null });
      },
      assist: async (auth, id, b) =>
        liveMessage((await call(auth, 'POST', '/matters/' + id + '/assist', b)).message),
      addDocument: async (auth, id, b) =>
        liveDocument((await call(auth, 'POST', '/matters/' + id + '/documents', b)).document),
      // The list the stand-in never needed and a reload in live mode cannot do without.
      listDocuments: async (auth, id) =>
        ((await call(auth, 'GET', '/matters/' + id + '/documents')).documents || [])
          .map(liveDocument),
      notarize: notarize,
      notarizeMessage: async (auth, id, mid) => {
        const r = await call(auth, 'POST', '/matters/' + id + '/messages/' + mid + '/notarize', {});
        return { record: r.record, document: r.document || null,
                 redaction: r.redaction || null, charged: r.charged || null };
      },
      notarizeThread: async (auth, id) => {
        const r = await call(auth, 'POST', '/matters/' + id + '/thread/notarize', {});
        return { record: r.record, document: r.document || null,
                 redaction: r.redaction || null, charged: r.charged || null };
      },
      progress: async (auth, id) => liveProgress(await call(auth, 'GET', '/matters/' + id + '/progress')),
      issueCertificate: issueCertificate,
      close: (auth, id, b) => call(auth, 'POST', '/matters/' + id + '/close', b),
    };
  }

  /* --------------------------------------------------------- rule check */
  // Runs in node and in the browser: node -e "require(...crypto.js);require(...ui.js);
  // require(...workplace.js); Bailee.workplace.selfTest().then(console.log)"
  // If the stand-in ever stops enforcing a rule, this says so out loud.
  async function selfTest() {
    const out = [];
    const ok = (name, pass, note) => out.push({ name, pass: !!pass, note: note || '' });
    const refuses = async (name, status, fn) => {
      try { await fn(); ok(name, false, 'it was allowed'); }
      catch (e) { ok(name, e.status === status, e.status + ' ' + e.message); }
    };

    const api = createLocalApi();
    const firm = { role: 'firm', key: api.firmKey };
    const lawyer = { role: 'lawyer', key: api.firmKey, interactive: true };
    const robot = { role: 'lawyer', key: api.firmKey, interactive: false };
    const service = { role: 'service', key: 'svc_key_0001' };

    const made = await api.createMatter(firm, { title: 'Test', clientName: 'A client' });
    const id = made.matterId;
    const enrolToken = made.clientEnrolUrl.split('=')[1];
    const enrolled = await api.enrol(id, enrolToken);
    const client = { role: 'client', key: enrolled.participantToken };

    await refuses('R1 a message with no origin is refused', 400,
      () => api.postMessage(client, id, { body: 'hello' }));
    await refuses('R1 a model message with no model id is refused', 400,
      () => api.postMessage(lawyer, id, { body: 'hello', origin: 'model' }));

    const cm = await api.postMessage(client, id, { body: 'They stopped shipping.', origin: 'human' });
    ok('R4 kind defaults to draft, not advice', cm.kind === 'draft', cm.kind);
    ok('R6 the client side is live', cm.sent === true);
    await refuses('a client with the VPN disconnected cannot send', 403,
      () => api.postMessage(Object.assign({}, client, { vpn: false }), id, { body: 'hi', origin: 'human' }));

    const draft = await api.assist(lawyer, id, { prompt: 'do we have a claim' });
    ok('R2 model output lands unsent in the lawyer pane', draft.sent === false && draft.origin === 'model');
    ok('R1 the draft names its model', draft.modelId === MODEL.id, draft.modelId);

    const clientSees = await api.thread(client, id);
    ok('R2 the client thread does not contain the unsent draft',
      clientSees.messages.filter((x) => x.id === draft.id).length === 0,
      clientSees.messages.length + ' message(s) visible');
    const lawyerSees = await api.thread(lawyer, id);
    ok('the lawyer thread does contain it', lawyerSees.messages.filter((x) => x.id === draft.id).length === 1);

    await refuses('R3 a service key cannot send', 403, () => api.send(service, id, { messageId: draft.id }));
    await refuses('R3 a non-interactive lawyer key cannot send', 403, () => api.send(robot, id, { messageId: draft.id }));
    await refuses('R3 the client cannot send the lawyer\'s draft', 403, () => api.send(client, id, { messageId: draft.id }));

    const sent = await api.send(lawyer, id, { messageId: draft.id, kind: 'advice' });
    ok('R2 send records the sending key: that is the adoption record', sent.sentBy === lawyer.key && !!sent.sentAt);
    ok('R4 kind is the sender\'s call', sent.kind === 'advice');
    const after = await api.thread(client, id);
    ok('R2 after sending, the client sees it', after.messages.filter((x) => x.id === draft.id).length === 1);
    await refuses('a message is adopted once', 409, () => api.send(lawyer, id, { messageId: draft.id }));

    const digest = CR.hex ? CR.hex(await CR.sha256('a clean file')) : ('0'.repeat(64));
    const clean = await api.addDocument(client, id, { filename: 'invoice.pdf', digest: digest, taint: false });
    const dirty = await api.addDocument(lawyer, id, {
      filename: 'draft-reply.txt', digest: CR.hex(await CR.sha256(draft.body)),
      taint: true, taintPath: 'message ' + draft.id + ' in a privileged thread',
    });
    await refuses('R5 notarize refuses a tainted document', 409, () => api.notarize(lawyer, id, { documentId: dirty.id }));
    const note = await api.notarize(client, id, { documentId: clean.id });
    ok('R5 a clean document notarizes', !!note.notarized && !!note.notarized.commitment);
    ok('either party may notarize', note.notarized.by === 'client');

    const held = await api.postMessage(lawyer, id, { body: 'Unsent thinking out loud.', origin: 'human' });
    const chat = await api.notarizeThread(client, id);
    ok('Notarize Chat commits once over the sent messages and leaves the unsent draft out',
      !!chat.record.commitment && chat.record.derivedFrom.indexOf(held.id) < 0
      && chat.record.derivedFrom.indexOf(draft.id) >= 0,
      chat.redaction.messageCount + ' message(s)');

    const prog = await api.progress(lawyer, id);
    const done = prog.stages.filter((s) => s.done).map((s) => s.id).join(' ');
    ok('the rail lights on real events only',
      done === 'opened client_enrolled documents_in work_in_progress notarized', done);

    await refuses('a stranger sees nothing', 403, () => api.thread({ role: 'client', key: 'nope' }, id));

    // Past the v1 contract: the stand-in can finish the rail so the screen can show it.
    await refuses('a matter does not close without an outcome', 400, () => api.close(lawyer, id, {}));
    await api.issueCertificate(lawyer, id, { documentId: clean.id });
    await api.close(lawyer, id, { outcome: 'Settled. Paid in full.' });
    const end = await api.progress(lawyer, id);
    ok('the rail can reach the end of the matter',
      end.stages.filter((s) => s.done).length === STAGES.length,
      end.stages.filter((s) => s.done).length + ' of ' + STAGES.length);

    const passed = out.filter((r) => r.pass).length;
    return { passed: passed, failed: out.length - passed, results: out };
  }

  /* ------------------------------------------- the same check, against an appliance */
  // selfTest() proves the stand-in still enforces the rules with no server. liveCheck()
  // proves the OTHER half: that this screen and a real appliance agree. Same state, same
  // seed, same renderers, real HTTP, real participant tokens, real 402 / 403 / 409.
  // No browser is needed and none is launched:
  //
  //   node -e "require('./site/app/crypto.js');require('./site/app/ui.js');
  //            require('./site/app/workplace.js');
  //            Bailee.workplace.liveCheck({ base: 'http://127.0.0.1:8402',
  //              firmKey: 'blf_lk_demo_cranmer_vale_0001',
  //              noCreditKey: 'blf_lk_demo_nocredit_0004' })
  //            .then(r => console.log(r.passed + ' passed, ' + r.failed + ' failed'))"
  async function liveCheck(opts) {
    const o = opts || {};
    const out = [];
    const ok = (name, pass, note) => out.push({ name: name, pass: !!pass, note: note || '' });
    const refuses = async (name, status, fn) => {
      try { await fn(); ok(name, false, 'it was allowed'); }
      catch (e) { ok(name, e.status === status, (e.status || '?') + ' ' + (e.message || '')); }
    };
    const fresh = (key) => ({
      party: 'client', api: createRemoteApi(o.base || 'http://127.0.0.1:8402'),
      matterId: null, clientToken: null, lawyerToken: null, maySend: true,
      lawyerName: 'Kevin G. Mohr, Esq.', firmKey: key, base: o.base,
      messages: [], docs: [], progress: null, log: [], banner: null,
      adoption: null, payment: null,
    });

    const st = fresh(o.firmKey);
    await seed(st);                                   // the same seed the page runs
    ok('the console holds an interactive lawyer session, not just a licence key',
      /^blf_wp_/.test(st.lawyerToken || ''), st.lawyerToken || 'none');
    ok('and the client holds their own participant token',
      /^blf_wp_/.test(st.clientToken || '') && st.clientToken !== st.lawyerToken);
    ok('the role switch swaps which credential is used',
      session(st, 'lawyer').key === st.lawyerToken
      && session(st, 'client').key === st.clientToken);

    st.party = 'client';
    await reload(st);
    const clientSees = st.messages.slice();
    ok('the client view holds no unsent lawyer draft',
      clientSees.every((m) => m.side === 'client' || m.sent));
    ok('every message the client is given can say where it came from',
      clientSees.length > 0
      && clientSees.every((m) => m.author && ORIGINS.indexOf(m.origin) >= 0
        && KINDS.indexOf(m.kind) >= 0));
    ok('so nothing on the client screen renders as Withheld',
      threadHtml(st).indexOf('Withheld') < 0);
    ok('maySend is false for the client', st.maySend === false);

    st.party = 'lawyer';
    await reload(st);
    ok('the lawyer pane opens with no model draft until someone asks the model',
      !st.messages.some((m) => m.side === 'lawyer' && !m.sent && m.origin === 'model'));
    await st.api.assist(session(st, 'lawyer'), st.matterId, { prompt: 'do we have a claim' });
    await reload(st);
    const draft = st.messages.filter((m) => m.side === 'lawyer' && !m.sent)[0];
    ok('the model output is in the lawyer pane, unsent and attributed to a model',
      !!draft && draft.origin === 'model' && !!draft.modelId, draft ? draft.modelId : 'no draft');
    ok('maySend is true for the interactive session', st.maySend === true);

    await refuses('the firm licence key cannot send', 403, () => st.api.send(
      { role: 'service', key: st.firmKey, interactive: false }, st.matterId,
      { messageId: draft.id }));
    await refuses('an unknown matter is a 403 that says nothing', 403,
      () => st.api.getMatter(session(st, 'lawyer'), 'mat_not_a_real_matter'));

    const sent = await st.api.send(session(st, 'lawyer'), st.matterId,
      { messageId: draft.id, kind: 'advice' });
    st.adoption = sent.adoption;
    ok('the send comes back with an adoption record naming the sending key',
      !!(sent.adoption && sent.adoption.sendRecordDigest && sent.adoption.sendingKeyHash));
    st.party = 'client';
    await reload(st);
    ok('and now it is in the client view',
      st.messages.some((m) => m.id === draft.id && m.sent));

    // documents: out of the thread is tainted, the client's own material is not
    const dirty = await st.api.addDocument(session(st, 'lawyer'), st.matterId, {
      filename: 'draft-' + draft.id + '.txt',
      digest: CR.hex(await CR.sha256(draft.body)),
      taint: false, derivedFrom: [draft.id],
    });
    ok('a document saved out of a thread message is tainted whatever the page declared',
      dirty.taint === true && !!dirty.taintPath, dirty.taintPath || '');
    await refuses('and notarize refuses it', 409,
      () => st.api.notarize(session(st, 'client'), st.matterId, { documentId: dirty.id }));

    const clean = await st.api.addDocument(session(st, 'client'), st.matterId, {
      filename: 'bank-statement.pdf', digest: CR.hex(await CR.sha256('the client own file')),
    });
    const noted = await st.api.notarize(session(st, 'client'), st.matterId,
      { documentId: clean.id });
    ok('a clean document notarises and is charged one cent',
      !!(noted.notarized && noted.notarized.commitment) && noted.charged
      && noted.charged.cents === 1,
      noted.charged ? '$' + noted.charged.balanceUsd + ' left' : '');

    await reload(st);
    ok('the document list survives a reload, with its state', st.docs.length === 2
      && st.docs.some((d) => d.notarized) && st.docs.some((d) => d.taint));
    ok('the documents panel shows the taint and the commitment',
      docsHtml(st).indexOf('tainted') > 0 && docsHtml(st).indexOf('notarized') > 0);

    // Notarize Chat: one record over the sent messages, never an unsent draft.
    const held = await st.api.postMessage(session(st, 'lawyer'), st.matterId,
      { body: 'Unsent thinking out loud.', origin: 'human', kind: 'draft' });
    const chat = await st.api.notarizeThread(session(st, 'client'), st.matterId);
    ok('Notarize Chat commits once over every sent message and leaves the unsent draft out',
      !!(chat.record && chat.record.commitment) && chat.record.derivedFrom.indexOf(held.id) < 0
      && chat.record.derivedFrom.indexOf(draft.id) >= 0 && chat.redaction.messageCount >= 2,
      chat.redaction.messageCount + ' message(s)');

    const cert = await st.api.issueCertificate({ role: 'firm', key: st.firmKey }, st.matterId,
      { document: st.docs.filter((d) => d.notarized)[0], adoption: st.adoption,
        lawyerName: st.lawyerName });
    ok('a certificate issued against the matter completes filed', !!cert.id);
    await st.api.close(session(st, 'lawyer'), st.matterId, { outcome: 'Settled. Paid in full.' });
    await reload(st);
    const done = (st.progress.stages || []).filter((s) => s.done).map((s) => s.id);
    ok('every stage on the rail completed on a real event: ' + done.join(' '),
      done.length === STAGES.length && st.progress.stages.every((s) => s.done && s.at));
    ok('and the rail draws from the live answer', railHtml(st.progress).indexOf('Closed') > 0);

    // 402: the price, quoted, on a licence with nothing left to spend
    if (o.noCreditKey) {
      const poor = fresh(o.noCreditKey);
      await seed(poor);
      const doc = await poor.api.addDocument(session(poor, 'lawyer'), poor.matterId, {
        filename: 'clean.pdf', digest: CR.hex(await CR.sha256('nothing privileged here')),
      });
      try {
        await poor.api.notarize(session(poor, 'lawyer'), poor.matterId, { documentId: doc.id });
        ok('workplace notarize is metered', false, 'it was free');
      } catch (e) {
        ok('workplace notarize is metered: no credit, 402', e.status === 402, e.message);
        poor.payment = paymentTerms(e, doc.id);
        const panel = paymentHtml(poor);
        ok('the console shows the 402 as terms, not as an error',
          /payment required/i.test(panel) && panel.indexOf('not an error') > 0);
        ok('naming a real address on the right network: ' + poor.payment.network + ' '
          + trim(poor.payment.payTo, 16),
          /^addr/.test(poor.payment.payTo) && poor.payment.payTo.indexOf('PLACEHOLDER') < 0
          && !!poor.payment.network);
      }
    }

    const passed = out.filter((r) => r.pass).length;
    return { passed: passed, failed: out.length - passed, results: out };
  }

  /* ------------------------------------------------------------- the screen */

  // Which credential this view is holding. The role switch does not change a flag on one
  // key: it swaps the key. An interactive lawyer session is a real credential — a
  // blf_wp_ participant token minted once at /enrol — and it is the only thing the API
  // will accept on /send. The firm's licence key can draft and can never adopt, so the
  // lawyer view uses the licence key only when there is no session yet (which is the
  // offline stand-in, where the firm key IS the lawyer).
  function session(st, as) {
    const who = as || st.party;
    if (who === 'client') return { role: 'client', key: st.clientToken, vpn: st.vpn !== false };
    return { role: 'lawyer', key: st.lawyerToken || st.firmKey, interactive: true };
  }

  function note(st, level, text, extra) {
    st.log.unshift({ at: new Date(), level: level, text: text, extra: extra || '' });
    st.log = st.log.slice(0, 10);
  }

  const pathText = (p) => (Array.isArray(p) ? p.join(' \u2192 ') : String(p || ''));

  function logError(st, e) {
    const path = e && e.taintPath ? ' \u2014 ' + pathText(e.taintPath) : '';
    note(st, 'refused', (e.status || '?') + ' ' + (e.message || 'refused') + path);
    // A 403 from this API is not "it exists, but not for you". An unknown matter and
    // another party's matter are the same answer, byte for byte, so the screen must not
    // report one as the other — that would be the leak the API refuses to make.
    if (e && e.status === 403 && e.error === 'wrong_party') {
      note(st, 'refused', 'That answer does not mean the matter exists. Unknown matter and '
        + 'someone else\u2019s matter are identical here, on purpose.');
    }
  }

  /* -- pieces -- */

  function railHtml(prog) {
    if (!prog || !prog.stages) return '';
    return '<ol class="wp-rail">' + prog.stages.map(function (s) {
      const cls = s.done ? 'is-done' : (s.id === prog.next ? 'is-next' : '');
      return '<li class="wp-stage ' + cls + '"><span class="wp-dot"></span>'
        + '<b>' + esc(s.label) + '</b>'
        + '<small>' + esc(s.done ? (s.note || s.why) : s.why) + '</small></li>';
    }).join('') + '</ol>';
  }

  // Nothing renders without attribution. This is the render-side half of R1: even if a
  // row somehow existed, the screen would refuse to show it as a message.
  function msgHtml(m, party, record) {
    if (!m || !m.author || ORIGINS.indexOf(m.origin) < 0 || KINDS.indexOf(m.kind) < 0) {
      return '<article class="wp-msg wp-void"><p>Withheld. This message cannot say where it '
        + 'came from, so it is not rendered.</p></article>';
    }
    const unsent = m.side === 'lawyer' && !m.sent;
    const cls = 'wp-msg wp-' + esc(m.side) + (unsent ? ' wp-unsent' : '') + (m.origin === 'model' ? ' wp-model' : '');
    const who = esc(m.author) + ' \u00b7 ' + (m.side === 'client' ? 'client' : 'lawyer');
    const chips = '<span class="chip' + (m.origin === 'model' ? ' on' : '') + '">'
      + (m.origin === 'model' ? 'model' : 'human') + '</span>'
      + (m.modelId ? '<span class="chip">' + esc(m.modelId) + '</span>' : '')
      + '<span class="chip">' + esc(KIND_LABEL[m.kind] || m.kind) + '</span>';
    let foot = '';
    if (unsent) {
      // The thread is the conversation. Everything you can DO with a draft lives in the
      // compose bar below, where the words you are looking at are the words that go.
      foot = '<div class="wp-hold"><b>The client cannot see this yet.</b> '
        + 'It is a draft in your pane, open in the box below. Sending it is adopting it.</div>';
    } else if (m.sentBy) {
      foot = '<div class="wp-foot">' + (m.side === 'lawyer'
        ? 'Sent by ' + esc(UI.short ? UI.short(m.sentBy, 8) : m.sentBy) + '. That record is the adoption record.'
        : 'Live. The client\u2019s own work.')
        + ' <span class="mono">' + esc(String(m.sentAt || m.at).slice(11, 19)) + '</span></div>';
    }
    // One click from the thread to the Document Record. Not "export, then hash what you
    // exported" \u2014 that leaves a gap where the words can change.
    const notarised = record
      ? '<div class="wp-foot">Notarised. <span class="mono">' + esc(String(record.commitment).slice(0, 16))
        + '\u2026</span> ' + esc(String(record.identifiersRemoved)) + ' identifier(s) redacted here first.</div>'
        + (party === 'client' ? '<div class="wp-foot">Logged for the firm. Only the lawyer certifies.</div>'
          : '<div class="wp-sendrow"><button class="btn" data-act="certify-msg" data-id="'
            + esc(m.id) + '">Certify this message</button></div>')
      : '<div class="wp-sendrow"><button class="btn ghost" data-act="notarize-msg" data-id="'
        + esc(m.id) + '">Notarize this message</button></div>';
    return '<article class="' + cls + '"><header class="wp-attrib"><b>' + who + '</b>'
      + '<span class="wp-chips">' + chips + '</span></header>'
      + '<p>' + esc(m.body) + '</p>' + foot + notarised + '</article>';
  }

  function threadHtml(st) {
    const all = st.messages || [];
    // The draft you are working on is in the box below, not doubled as a card up here.
    // Any OLDER unsent draft stays visible: nothing the firm holds is hidden from the firm.
    const working = st.party === 'client' ? null
      : all.filter((m) => m.side === 'lawyer' && !m.sent).slice(-1)[0];
    const list = working ? all.filter((m) => m.id !== working.id) : all;
    const head = st.party === 'client'
      ? 'What the client sees'
      : 'What the lawyer sees';
    const sub = st.party === 'client'
      ? 'Everything sent to you, plus your own messages. You never see your lawyer\u2019s unsent '
        + 'drafts, because nothing reaches you until the lawyer presses Send.'
      : 'The full conversation, including drafts the client cannot see yet. The draft you are '
        + 'working on sits in the box below until you press Send.';
    const body = list.length
      ? list.map((m) => msgHtml(m, st.party, (st.records || {})[m.id])).join('')
      : '<p class="muted">Nothing in this thread yet.</p>';
    return '<div class="panel wp-thread"><h3>' + esc(head) + help(sub) + '</h3>' + body + '</div>';
  }

  const sentIds = (st) => (st.messages || []).filter((m) => m.sent || m.sentAt).map((m) => m.id).join(',');
  const chatRecord = (st) => (st.chatRecord && st.chatRecord.ids === sentIds(st) ? st.chatRecord : null);

  function composeHtml(st) {
    const client = st.party === 'client';
    // The lawyer's unsent draft is not a card with buttons in the thread: it is open in
    // this box. What you read here is what gets adopted.
    const pending = client ? null : (st.messages || [])
      .filter((m) => m.side === 'lawyer' && !m.sent).slice(-1)[0];
    const cannot = !client && st.maySend === false
      ? '<p class="bad">This view is holding the firm\u2019s licence key, not an interactive '
        + 'lawyer session. It can draft and ask the model. Every send will be refused 403.</p>'
      : '';
    const pick = (id, label, list, chosen) => '<label class="wp-pick"><span>' + esc(label) + '</span>'
      + '<select class="wp-select" id="' + esc(id) + '" data-act="' + esc(id) + '">'
      + list.map(function (o) {
        return '<option value="' + esc(o[0]) + '"' + (o[0] === chosen ? ' selected' : '') + '>'
          + esc(o[1]) + '</option>';
      }).join('') + '</select></label>';
    const kindPick = !client
      ? '<label class="wp-pick"><span>Kind</span><select class="wp-kind wp-select" id="wp-kind"'
        + (pending ? ' data-id="' + esc(pending.id) + '"' : '') + ' aria-label="Kind">'
        + KINDS.map((k) => '<option value="' + k + '"'
            + (pending && k === pending.kind ? ' selected' : '') + '>' + esc(KIND_LABEL[k])
            + '</option>').join('')
        + '</select></label>'
      : '';
    // The whole chat, one record. A record made before the last send is stale, so the
    // button goes back to Notarize Chat rather than certify something that is no longer all of it.
    const chat = chatRecord(st);
    const chatBtn = chat
      ? (client ? '<span class="muted">Chat notarized. Logged for the firm.</span>'
        : '<button class="btn ghost" data-act="certify-chat">Certify this chat</button>')
      : '<button class="btn ghost" data-act="notarize-chat">Notarize Chat</button>'
        + help('Records a tamper-proof fingerprint of every sent message in this chat, with names '
          + 'and contact details removed first. Costs one notarization ($0.01).');
    const sendRow = pending
      ? '<button class="btn" data-act="send" data-id="' + esc(pending.id) + '">Send (this is adoption)</button>'
        + '<button class="btn ghost" data-act="send-auto" data-id="' + esc(pending.id)
        + '">Try an automated send</button>'
      : '<button class="btn" data-act="post"' + (client && !st.vpn ? ' disabled title="Connect the VPN first"' : '')
        + '>' + (client ? 'Send' : 'Hold as a draft') + '</button>';
    const vpn = client
      ? '<div class="wp-vpn"><button class="btn ghost" data-act="vpn">' + (st.vpn ? 'Disconnect VPN' : 'Connect VPN')
        + '</button><span class="wp-vpn-status' + (st.vpn ? ' on' : '') + '" role="status">'
        + (st.vpn ? 'Connected' : 'Disconnected') + '</span>'
        + help('Your messages travel over a private VPN to your law firm. Connect it before you '
          + 'send. While it is disconnected, the firm\u2019s system refuses your messages.') + '</div>'
      : '';
    return '<div class="panel wp-compose' + (client ? ' local' : ' chain') + '">'
      + cannot + vpn
      + wmField({ id: 'wp-text', label: client ? 'Write to your lawyer' : 'Write to your client',
          options: [pending ? pending.body : ''], multiline: true, rows: 3,
          help: client
            ? 'Type a message to your lawyer. It is labelled as written by you, stays inside this '
              + 'private thread, and only you and your law firm can see it.'
            : 'The AI\u2019s draft appears here. Edit it if you need to, then press Send. Sending means '
              + 'you adopt it as your own, and the record names you.' })
      + '<div class="wp-composebar">'
      + '<div class="wp-composeleft">'
      + '<label class="btn ghost wp-attach" for="wp-file">Attach a document</label>'
      + '<input type="file" id="wp-file" class="wp-file">'
      + kindPick
      + pick('wp-model', 'Model', MODELS, st.model)
      + pick('wp-harness', 'Harness', HARNESSES, st.harnessBy[st.party])
      + '</div>'
      + '<div class="actions">'
      + chatBtn
      + '<button class="btn ghost" data-act="assist">Ask the model</button>'
      + sendRow
      + '</div></div></div>';
  }


  // The Certificate Generator, opened over the matter instead of in another tab. Same
  // widget, same code: only the fields it cannot know are filled in from here, and never
  // an identifier \u2014 a certificate carries none.
  function openCertify(st, digest, commitment) {
    const dlg = typeof document !== 'undefined' ? document.getElementById('wp-certify') : null;
    if (!dlg || !digest) return;
    const put = function (sel, value) {
      const box = dlg.querySelector(sel);
      if (box && value) { box.value = value; }
    };
    put('#ct-digest', digest);
    put('#ct-atty', st.lawyerName);
    const model = (st.messages || []).filter((x) => x.modelId)[0];
    if (model) put('#ct-modelver', model.modelId);
    if (UI.emit) UI.emit('bailee:certify', { digest: digest, commitment: commitment || '' });
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', 'open');
    note(st, 'ok', 'Certificate generator opened over this matter with that digest already '
      + 'in it. Nothing identifying the client is carried across.');
  }

  function docsHtml(st) {
    const rows = (st.docs || []).map(function (d) {
      const state = d.taint
        ? '<span class="bad">tainted</span><small class="wp-path">' + esc(d.taintPath || '') + '</small>'
        : (d.notarized ? '<span class="ok">notarized</span>' : '<span class="muted">clean</span>');
      const act = d.notarized
        ? '<code>' + esc(UI.short ? UI.short(d.notarized.commitment, 8) : d.notarized.commitment) + '</code>'
          + ' <button class="btn ghost" data-act="certify" data-id="' + esc(d.id) + '">Certify this document</button>'
          + (st.api.extras ? ' <button class="btn ghost" data-act="cert" data-id="' + esc(d.id) + '">Issue certificate</button>' : '')
        : '<button class="btn ghost" data-act="notarize" data-id="' + esc(d.id) + '">Notarize</button>';
      return '<tr><td>' + esc(d.filename) + '</td><td class="mono">'
        + esc(UI.short ? UI.short(d.digest, 8) : d.digest) + '</td><td>' + state + '</td><td>' + act + '</td></tr>';
    }).join('');
    return '<div class="panel wp-docs"><h3>Documents' + help('Attached files are fingerprinted in your browser. The file itself never leaves. A document copied out of the private thread is flagged, and cannot be notarized.') + '</h3>'
      + (rows ? '<table><thead><tr><th>File</th><th>SHA-256</th><th>State</th><th></th></tr></thead><tbody>'
          + rows + '</tbody></table>' : '<p class="muted">No documents yet.</p>')
      + '</div>';
  }

  // 402 is a first-class outcome, so it gets a panel of its own rather than a red line in
  // the log. x402 terms are machine-readable on purpose: a wallet can act on this.
  function paymentTerms(e, documentId) {
    const t = (e && e.accepts && e.accepts[0]) || {};
    return {
      documentId: documentId,
      amount: t.amount || '', asset: (t.extra && t.extra.name) || t.asset || '',
      network: t.network || '', payTo: t.payTo || '',
      message: (e && e.message) || '',
      settlement: (e && e.settlement && e.settlement.detail) || '',
    };
  }

  function paymentHtml(st) {
    const p = st.payment;
    if (!p) return '';
    return '<div class="panel wp-pay"><h3>Payment Required \u2014 402' + help('This is the price, not an error. A notarization costs $0.01 from the licence balance. This licence has too little left, so nothing was saved or charged.') + '</h3>'
      + '<p><span class="chip on">' + esc(p.amount) + ' ' + esc(p.asset) + '</span> '
      + '<span class="chip">' + esc(p.network) + '</span></p>'
      + '<p class="mono wp-path">pay to ' + esc(p.payTo) + '</p>'
      + (p.settlement ? '<p class="wp-sub">' + esc(p.settlement) + '</p>' : '')
      + '<div class="actions">'
      + '<button class="btn ghost" data-act="notarize" data-id="' + esc(p.documentId)
      + '">Try the notarisation again</button>'
      + '<button class="btn ghost" data-act="dismiss-pay">Dismiss</button>'
      + '</div></div>';
  }

  function logHtml(st) {
    if (!st.log.length) return '';
    const rows = st.log.map(function (l) {
      return '<li class="wp-log-' + esc(l.level) + '"><span class="mono">'
        + esc(l.at.toLocaleTimeString('en-US', { hour12: false })) + '</span> ' + esc(l.text) + '</li>';
    }).join('');
    return '<details class="panel wp-loglist wp-fold"><summary>What the API Did'
      + ' <span class="chip">' + st.log.length + '</span></summary><ul>' + rows + '</ul></details>';
  }

  function barHtml(st) {
    return '<div class="wp-bar">'
      + '<div class="wp-switch" role="group" aria-label="View as">'
      + '<button class="' + (st.party === 'client' ? 'on' : '') + '" aria-pressed="'
      + (st.party === 'client') + '" data-act="role" data-role="client">View as client</button>'
      + '<button class="' + (st.party === 'lawyer' ? 'on' : '') + '" aria-pressed="'
      + (st.party === 'lawyer') + '" data-act="role" data-role="lawyer">View as lawyer</button>'
      + '</div>'
      + '</div>'
      // The free key, in plain sight. Nobody should have to open a panel to find it.
      + '<p class="wp-lic">Free demo licence key <code data-copy="' + esc(DEMO_LICENCE) + '">'
      + esc(DEMO_LICENCE) + '</code>' + help('The firm\u2019s password for the appliance. It opens cases and pays for each certification ($0.10) and notarization ($0.01). It can never send a message; only a named lawyer can.') + '</p>';
  }

  // Which matter the demo opens. Nothing is typed in for anyone: a title, a client and a
  // lawyer are chosen from a list, or written in, and the matter is opened through the
  // same createMatter() call the rest of the screen uses.
  function matterHtml(st) {
    return '<div class="panel wp-matter"><h3>The Matter This Demo Opens' + help('The case this demo opens. Change the names and press Reset to start a fresh case. Everything runs through the same API a real firm would use.') + '</h3>'
      + '<div class="inline">'
      + wmField({ id: 'wp-title', label: 'Matter title', options: MATTER_TITLES, value: st.matterTitle })
      + wmField({ id: 'wp-client', label: 'Client name', options: CLIENT_NAMES, value: st.clientName })
      + wmField({ id: 'wp-lawyer', label: 'Lawyer', options: LAWYER_NAMES, value: st.lawyerName })
      + '<button class="btn ghost" data-act="reopen">Reset</button>'
      + '</div></div>';
  }

  function closeHtml(st) {
    if (!st.api.extras || st.party !== 'lawyer') return '';
    return '<div class="panel wp-close"><h3>Outcome' + help('Where the case ends. Notarize a finished document or close the matter here. The progress bar above lights up only when these things actually happen.') + '</h3>'
      + '<div class="inline">'
      + wmField({ id: 'wp-outcome', label: 'Close the matter',
          options: [{ value: '', label: '\u2014 no outcome yet \u2014' }].concat(OUTCOMES) })
      + '<button class="btn ghost" data-act="close">Close</button></div>'
      + '</div>';
  }

  function paint(st, el) {
    const slot = UI.$(el, '#wp-body');
    if (!slot) return;
    slot.innerHTML = barHtml(st) + matterHtml(st)
      + (st.banner ? '<p class="bad">' + esc(st.banner) + '</p>' : '')
      + railHtml(st.progress)
      + threadHtml(st) + composeHtml(st)
      + paymentHtml(st) + docsHtml(st) + closeHtml(st) + logHtml(st);
  }

  async function reload(st) {
    const auth = session(st);
    try {
      const th = await st.api.thread(auth, st.matterId);
      st.messages = th.messages || [];
      // The API says whether this credential may adopt. The screen believes it rather
      // than guessing from the role switch.
      st.maySend = th.youAre ? th.youAre.maySend !== false : true;
      st.progress = await st.api.progress(auth, st.matterId);
      // Live mode has a real list, so the documents survive a reload instead of being
      // whatever this page happened to see come back from a POST.
      if (st.api.listDocuments) st.docs = await st.api.listDocuments(auth, st.matterId);
      st.banner = null;
    } catch (e) {
      st.banner = (e.status || '') + ' ' + e.message;
      logError(st, e);
    }
  }

  // The stand-in hands back `workplace.html#enrol=<token>`; the appliance hands back
  // `/v1/workplace/matters/<id>/enrol#<token>` and the token in its own field as well.
  const tokenFrom = (u) => {
    const s = String(u || '');
    const q = s.match(/(?:enrol|token)=([^&#\s]+)/);
    if (q) return q[1];
    const frag = s.match(/#([^#\s/]+)$/);
    return frag ? frag[1] : s;
  };

  // Open a matter and put two people in it, through the API, obeying every rule. The seed
  // has no back door: it is the same calls the buttons make.
  async function seed(st) {
    const firm = { role: 'firm', key: st.firmKey };
    const made = await st.api.createMatter(firm, {
      title: st.matterTitle || MATTER_TITLES[0],
      clientName: st.clientName || CLIENT_NAMES[0],
    });
    st.matterId = made.matterId;

    // TWO enrolments, not one. The appliance issues a one-time token per side, and the
    // lawyer's is not a convenience: it mints the interactive session that is the only
    // credential /send accepts. A console that enrols only the client has a thread it
    // can draft in and can never send from.
    const lawyerLink = made.lawyerEnrolToken || made.lawyerEnrolUrl;
    if (lawyerLink) {
      const lawyer = await st.api.enrol(st.matterId, tokenFrom(lawyerLink), st.lawyerName);
      st.lawyerToken = lawyer.participantToken;
    }
    const enrolled = await st.api.enrol(
      st.matterId, tokenFrom(made.clientEnrolToken || made.clientEnrolUrl), made.clientName);
    st.clientToken = enrolled.participantToken;

    await st.api.postMessage({ role: 'client', key: st.clientToken }, st.matterId, {
      body: OPENING_MESSAGE, origin: 'human', kind: 'draft',
    });
    // No model draft yet: the lawyer asks for one with "Ask the model".
    note(st, 'ok', 'Matter opened. ' + (st.lawyerToken
      ? 'Both sides enrolled: the lawyer holds an interactive session, the client holds theirs. '
      : 'Client enrolled. ')
      + 'Press Ask the model for a draft.');
  }

  async function act(st, el, name, target) {
    const id = target && target.dataset ? target.dataset.id : null;
    // The compose box is a dropdown ending in "Write my own", so a chosen line and a
    // typed one reach the API by the same path.
    const text = () => wmValue(el, 'wp-text');
    const clear = () => wmReset(el, 'wp-text');
    const auth = session(st);

    try {
      if (name === 'vpn') {
        st.vpn = !st.vpn;
        note(st, 'ok', st.vpn ? 'Client VPN connected. The client can send.'
          : 'Client VPN disconnected. Client messages are refused until it reconnects.');
      } else if ((name === 'certify-chat' || name === 'certify-msg') && st.party === 'client') {
        note(st, 'bad', 'Only the lawyer certifies. The client\u2019s notarizations are logged for the firm.');
      } else if (name === 'post' && st.party === 'client' && !st.vpn) {
        note(st, 'bad', 'Not sent. Connect the VPN first.');
      } else if (name === 'role') {
        st.party = target.dataset.role === 'lawyer' ? 'lawyer' : 'client';
        note(st, 'ok', 'Viewing as the ' + st.party + '. The thread is re-fetched for that party.');
      } else if (name === 'post') {
        const m = await st.api.postMessage(auth, st.matterId, {
          body: text(), origin: 'human', kind: 'draft',
        });
        clear();
        note(st, 'ok', st.party === 'client'
          ? 'Client message stored and visible. Their side is live.'
          : 'Held as an unsent draft. ' + m.id + ' is not in the client\u2019s view.');
      } else if (name === 'assist') {
        const m = await st.api.assist(auth, st.matterId,
          { prompt: text(), model: st.model, harness: st.harnessBy[st.party] });
        clear();
        note(st, 'ok', st.party === 'lawyer'
          ? 'Model output landed in the lawyer pane as an unsent draft, attributed to ' + m.modelId + '.'
          : 'Model output in the client\u2019s own pane, attributed to ' + m.modelId + '.');
      } else if (name === 'send') {
        const sel = el.querySelector('.wp-kind[data-id="' + id + '"]');
        // What is in the box is what gets adopted. If the lawyer edited the draft, the
        // edit is stored as a new draft first: sending the old text while showing the new
        // text would be the page lying about what was adopted.
        let sendId = id;
        const draft = (st.messages || []).filter((x) => x.id === id)[0];
        const typed = text();
        if (draft && typed && typed.trim() !== String(draft.body || '').trim()) {
          const edited = await st.api.postMessage(auth, st.matterId,
            { body: typed, origin: 'human', kind: sel ? sel.value : 'draft' });
          sendId = edited.id;
          note(st, 'ok', 'Your edit was stored as the draft that is about to be sent.');
        }
        const m = await st.api.send(session(st, 'lawyer'), st.matterId,
          { messageId: sendId, kind: sel ? sel.value : 'draft' });
        // Keep the adoption record: it is the evidence for one of the four claims on a
        // certificate, and the appliance only hands it over once, here.
        if (m.adoption) st.adoption = m.adoption;
        note(st, 'ok', 'Sent as ' + (KIND_LABEL[m.kind] || m.kind)
          + '. The sending key is on the record. That record is the adoption.');
      } else if (name === 'send-auto') {
        // The firm's own licence key on the send endpoint. That key is exactly what a cron
        // job holds, so this is the auto-responder, built out of a real credential rather
        // than an invented one, and it must be impossible rather than discouraged.
        await st.api.send({ role: 'service', key: st.firmKey, interactive: false },
          st.matterId, { messageId: id });
      } else if (name === 'notarize-chat') {
        try {
          const out = await st.api.notarizeThread(auth, st.matterId);
          const red = out.redaction || { identifiersRemoved: 0, messageCount: 0 };
          st.chatRecord = { ids: sentIds(st), commitment: (out.record || {}).commitment || '',
                            digest: (out.document || {}).digest || '' };
          if (root.Bailee && root.Bailee.profile) {
            root.Bailee.profile.record({
              kind: 'notarization', title: (st.matterTitle || 'Matter') + ' — whole chat',
              matter: st.matterTitle || 'Matter', by: st.party,
              commitment: st.chatRecord.commitment, digest: st.chatRecord.digest,
              identifiersRemoved: red.identifiersRemoved || 0,
            });
          }
          // A client notarization is a log entry for the firm; only the lawyer's moves the work on.
          if (UI.emit && st.party === 'lawyer') UI.emit('bailee:notarized', { scope: 'chat', digest: st.chatRecord.digest,
            commitment: st.chatRecord.commitment, title: st.matterTitle });
          note(st, 'ok', (st.party === 'client' ? 'Client notarization, logged for the firm. ' : '') + 'Chat notarised: ' + (red.messageCount || 0) + ' sent message(s) in one record. '
            + 'The appliance redacted them first: ' + (red.identifiersRemoved || 0) + ' identifier(s) out.');
        } catch (e) {
          if (e.status !== 402) throw e;
          st.payment = paymentTerms(e, null);
          note(st, 'ok', '402 Payment required. Nothing was recorded and nothing was '
            + 'charged — the terms are below.');
        }
      } else if (name === 'certify-chat') {
        const rec = chatRecord(st);
        if (rec && rec.digest) openCertify(st, rec.digest, rec.commitment);
      } else if (name === 'notarize') {
        try {
          const d = await st.api.notarize(auth, st.matterId, { documentId: id });
          st.docs = st.docs.map((x) => (x.id === d.id ? d : x));
          st.payment = null;
          if (root.Bailee && root.Bailee.profile) {
            root.Bailee.profile.record({
              kind: 'notarization', title: d.filename || st.matterTitle,
              matter: st.matterTitle || 'Matter', by: st.party,
              commitment: (d.notarized || {}).commitment || '', digest: d.digest,
            });
          }
          note(st, 'ok', 'Notarized. Commitment published, document not.'
            + (d.charged ? ' Charged $' + d.charged.usd + '; paid by '
                + d.charged.paidBy + '.' : ''));
        } catch (e) {
          // 402 is not a failure. It is the price, quoted. One Document Record entry is
          // one notarization whichever door it came through, so this endpoint bills
          // exactly like POST /v1/notarize and says so in x402 terms a wallet can act on.
          if (e.status !== 402) throw e;
          st.payment = paymentTerms(e, id);
          note(st, 'ok', '402 Payment required. Nothing was recorded and nothing was '
            + 'charged \u2014 the terms are below.');
        }
      } else if (name === 'notarize-msg') {
        try {
          const out = await st.api.notarizeMessage(auth, st.matterId, id);
          const red = out.redaction || { identifiersRemoved: 0, redactedBody: '' };
          st.records = st.records || {};
          st.records[id] = { commitment: (out.record || {}).commitment || '',
                             digest: (out.document || {}).digest || '',
                             identifiersRemoved: red.identifiersRemoved || 0 };
          if (UI.emit && st.party === 'lawyer') UI.emit('bailee:notarized', { scope: 'message', digest: st.records[id].digest,
            commitment: st.records[id].commitment, title: st.matterTitle });
          // The attorney's own history, on their own device.
          if (root.Bailee && root.Bailee.profile) {
            root.Bailee.profile.record({
              kind: 'notarization', title: st.matterTitle || 'Matter',
              matter: st.matterTitle || 'Matter', by: st.party,
              commitment: st.records[id].commitment, digest: st.records[id].digest,
              identifiersRemoved: red.identifiersRemoved || 0,
            });
          }
          note(st, 'ok', (st.party === 'client' ? 'Client notarization, logged for the firm. ' : '')
            + 'Notarised from the thread. The appliance redacted it first: '
            + (red.identifiersRemoved || 0) + ' identifier(s) out. What the commitment covers: "'
            + String(red.redactedBody || '').slice(0, 160) + '"');
        } catch (e) {
          if (e.status !== 402) throw e;
          st.payment = paymentTerms(e, id);
          note(st, 'ok', '402 Payment required. Nothing was recorded and nothing was '
            + 'charged \u2014 the terms are below.');
        }
      } else if (name === 'certify-msg') {
        const rec = (st.records || {})[id];
        if (rec && rec.digest) openCertify(st, rec.digest, rec.commitment);
      } else if (name === 'certify') {
        // The Certificate Generator, opened over the matter instead of in another tab.
        // Same widget, same code: only the fields it cannot know are filled in from here,
        // and never an identifier \u2014 a certificate carries none.
        const doc = (st.docs || []).filter((x) => x.id === id)[0];
        if (doc) openCertify(st, doc.digest, (doc.notarized || {}).commitment);
      } else if (name === 'cert') {
        const doc = (st.docs || []).filter((x) => x.id === id)[0];
        const model = (st.messages || []).filter((x) => x.origin === 'model')[0] || {};
        const c = await st.api.issueCertificate({ role: 'firm', key: st.firmKey }, st.matterId,
          { documentId: id, document: doc, adoption: st.adoption, modelId: model.modelId,
            lawyerName: st.lawyerName });
        note(st, 'ok', 'Certificate ' + trim(c.id, 12) + ' issued against the matter. '
          + 'The rail moves to filed.'
          + (c.demo ? ' Two of the four claims carry demonstration evidence.' : ''));
      } else if (name === 'close') {
        await st.api.close(auth, st.matterId, { outcome: wmValue(el, 'wp-outcome') });
        note(st, 'ok', 'Closed with an outcome.');
      } else if (name === 'dismiss-pay') {
        st.payment = null;
      } else if (name === 'reopen') {
        // Same three values the seed used, taken from the fields rather than from here.
        st.matterTitle = wmValue(el, 'wp-title') || st.matterTitle;
        st.clientName = wmValue(el, 'wp-client') || st.clientName;
        st.lawyerName = wmValue(el, 'wp-lawyer') || st.lawyerName;
        return start(st, el, st.api);
      }
    } catch (e) { logError(st, e); }

    await reload(st);
    paint(st, el);
  }

  async function start(st, el, api) {
    st.api = api;
    st.docs = [];
    st.messages = [];
    st.log = [];
    st.party = st.party === 'lawyer' ? 'lawyer' : 'client';
    // Credentials belong to the matter that is about to be opened, not to the page.
    st.clientToken = null;
    st.lawyerToken = null;
    st.adoption = null;
    st.payment = null;
    st.maySend = true;
    try {
      await seed(st);
    } catch (e) {
      logError(st, e);
      st.banner = 'This appliance did not let the demo open a matter: ' + e.message;
    }
    await reload(st);
    paint(st, el);
  }

  function render(el) {
    const st = {
      party: 'client', api: null, matterId: null,
      model: MODELS[0][0], vpn: false,
      // The client starts on redacted research: nothing identifying leaves their side by default.
      harnessBy: { client: 'redacted', lawyer: HARNESSES[0][0] },
      // Two participant tokens, because there are two parties and the API issues one to
      // each. The role switch swaps which one the page is holding.
      clientToken: null, lawyerToken: null, maySend: true,
      lawyerName: LAWYER_NAMES[0],
      matterTitle: MATTER_TITLES[0], clientName: CLIENT_NAMES[0],
      firmKey: 'firm_2a9f_cranmer_vale', base: '',
      messages: [], docs: [], progress: null, log: [], banner: null,
      adoption: null, payment: null,
    };

    el.innerHTML = '<h2>One Matter, Two Views'
      + help('One case, seen from both sides. Flip the switch to compare what the client sees with what the lawyer sees. The rules are real; the AI answers are placeholders.')
      + '</h2>'
      + '<div id="wp-body"></div>';

    // One delegated set of handlers for the dropdown/free-text fields. paint() only
    // replaces #wp-body, so these survive every repaint.
    wireFields(el);

    el.addEventListener('click', function (e) {
      const t = e.target.closest('[data-act]');
      // A select acts on change, not click: repainting on click tore down the open list.
      if (!t || t.tagName === 'SELECT') return;
      e.preventDefault();
      act(st, el, t.dataset.act, t);
    });

    el.addEventListener('change', async function (e) {
      // No repaint here: it would wipe whatever is typed in the compose box.
      if (e.target && e.target.id === 'wp-model') {
        st.model = e.target.value;
        note(st, 'ok', 'Model for the next request: ' + st.model + '. The appliance stub answers either way.');
        return;
      }
      if (e.target && e.target.id === 'wp-harness') {
        st.harnessBy[st.party] = e.target.value;
        note(st, 'ok', 'Harness for the next request: ' + e.target.value + '.');
        return;
      }
      if (!e.target || e.target.id !== 'wp-file') return;
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      try {
        const bytes = new Uint8Array(await f.arrayBuffer());
        const digest = CR.hex(await CR.sha256(bytes));
        const d = await st.api.addDocument(session(st), st.matterId,
          { filename: f.name, digest: digest, taint: false });
        st.docs.push(d);
        note(st, 'ok', f.name + ' hashed in this browser. The digest was registered. The file stayed here.');
      } catch (err) { logError(st, err); }
      await reload(st);
      paint(st, el);
    });

    start(st, el, createLocalApi({ firmKey: st.firmKey }));
  }

  if (UI.mount) UI.mount('workplace', render);

  root.Bailee.workplace = {
    MODEL, STAGES, ORIGINS, KINDS,
    createLocalApi, createRemoteApi, selfTest, liveCheck, render,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
