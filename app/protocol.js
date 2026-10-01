(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const { sha256, commit, hex, unhex, randomNonce, merkleRoot, merkleProof, verifyProof } = root.Bailee.crypto;
  const { mount, $, esc, wireCopy, monoBlock, row, short, nowISO,
    wmField, wmValue, wireFields } = root.Bailee.ui;

  // Client Communication Protocol — automatic, batched, one blinded root per period.
  // Two levels: every document commitment in a firm's period folds into one firm root,
  // and every firm's root folds into the single network root that is actually published.

  // Fixed-depth trees (C-06 / A-4). A raw Merkle proof over n leaves is n-shaped: its
  // length bounds the batch size, and its left/right bits spell out the leaf index. One
  // disclosed proof therefore handed opposing counsel the document count, the firm's
  // position and the document's position — the exact leak the panel below calls "the
  // dangerous leak". client_protocol.compact does not have this problem: its path is a
  // fixed MerkleTreePath<8>. So the demo now mirrors the contract instead of contradicting
  // it: every tree is padded to 2^8 = 256 slots with random 32-byte dummies, and the real
  // leaves are dropped into randomly chosen slots. Every proof is 8 steps whatever the
  // batch held, the side bits point at a random slot rather than at a position, and an
  // empty period still produces a root (A-5).
  const TREE_DEPTH = 8;
  const TREE_SLOTS = 1 << TREE_DEPTH;

  // Uniform in [0, n) by rejection sampling on 32 CSPRNG bits.
  function randomIndex(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    for (;;) {
      const b = randomNonce(4);
      const v = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
      if (v < limit) return v % n;
    }
  }

  // leaves -> a full 256-slot tree. `positions[i]` is the slot real leaf i landed in.
  async function periodTree(leaves) {
    if (leaves.length > TREE_SLOTS) {
      throw new Error(`a period holds at most ${TREE_SLOTS} leaves (MerkleTreePath<${TREE_DEPTH}>)`);
    }
    const slots = [];
    for (let i = 0; i < TREE_SLOTS; i++) slots.push(randomNonce(32));
    const free = slots.map((_, i) => i);
    const positions = leaves.map((leaf) => {
      const pick = free.splice(randomIndex(free.length), 1)[0];
      slots[pick] = leaf;
      return pick;
    });
    return { slots, positions, depth: TREE_DEPTH, root: await merkleRoot(slots) };
  }

  // A document's proof spans both trees and is produced only if the firm chooses to.
  // `docTree` is the firm's period tree, `netTree` the network tree over firm roots.
  async function documentProof(docTree, index, netTree, firmIndex) {
    return {
      leafProof: await merkleProof(docTree.slots, docTree.positions[index]),
      firmProof: await merkleProof(netTree.slots, netTree.positions[firmIndex]),
      firmRoot: hex(docTree.root),
    };
  }

  async function verifyDocumentProof(commitment, proof, publishedRoot) {
    const firmRoot = unhex(proof.firmRoot);
    const inFirm = await verifyProof(commitment, proof.leafProof, firmRoot);
    const inNetwork = await verifyProof(firmRoot, proof.firmProof, publishedRoot);
    return { inFirm, inNetwork, ok: inFirm && inNetwork };
  }

  // Every proof is the same shape, so this is now true of what we ship. The linkage line
  // stays because it is still true and it is the part a firm has to manage. Exported so
  // the self-test can pin the claim to the code.
  const PROOF_DISCLOSURE = 'Every proof is the same length \u2014 '
    + (TREE_DEPTH * 2) + ' sibling hashes, whatever the period held \u2014 because both trees are padded '
    + 'to a fixed ' + TREE_SLOTS + ' slots and the real leaves sit in randomly chosen ones. So the proof '
    + 'reveals the sibling hashes and nothing else: not the other documents, not the other firms, '
    + 'not how many of either there were, and not where in the batch this one sat. '
    + 'One thing it does carry: the firm root is the same in every proof you hand out this period, '
    + 'so two recipients can tell their proofs came from the same firm in the same period.';

  // `seed` is a real Document Record commitment (hex) handed over by the page, so the batch
  // carries the reader's own notarised record as communication #1 instead of a made-up one.
  async function pkBuild(nDocs, nFirms, ourFirm = 0, seed = '') {
    const docs = seed ? [{ label: 'your notarised record', commitment: unhex(seed) }] : [];
    for (let i = docs.length; i < nDocs; i++) {
      const label = `communication ${i + 1} \u2014 ${['advice', 'draft', 'strategy note', 'status update'][i % 4]}`;
      docs.push({ label, nonce: randomNonce(32), commitment: await commit(label, randomNonce(32)) });
    }
    const docTree = await periodTree(docs.map((d) => d.commitment));
    const firmRoots = [];
    for (let f = 0; f < nFirms; f++) {
      firmRoots.push(f === ourFirm ? docTree.root : await sha256('other firm ' + f + ':' + hex(randomNonce(16))));
    }
    const netTree = await periodTree(firmRoots);
    return { docs, docTree, ours: docTree.root, firmRoots, netTree, net: netTree.root, ourFirm };
  }


  function pkRender(el) {
    el.innerHTML = `
      <h2>Protocol root &mdash; what the chain actually sees</h2>
      <p class="lede">The Document Record is opt-in because it has consequences. The Protocol is
      automatic because it has none. It sweeps everything, batches it, and publishes one root per
      period on a fixed cadence &mdash; whether or not anything happened.</p>
      <div class="panel builder">
        <div class="inline">
          <div class="field"><label>Communications in your firm this period</label>
            <input id="pk-n" type="number" min="0" max="256" value="23"></div>
          <div class="field"><label>Firms sharing the network tree</label>
            <input id="pk-f" type="number" min="1" max="256" value="9"></div>
          ${wmField({ id: 'pk-p', label: 'Period', options: ['2026-W38', '2026-W39', '2026-W40'] })}
          <button class="btn" id="pk-go">Build the period root</button>
        </div>
      </div>
      <div id="pk-out"></div>`;

    wireCopy(el);
    wireFields(el);
    const out = $(el, '#pk-out');
    let S = null;

    async function build() {
      // 0 is allowed for documents: an empty period still publishes a root (A-5).
      const seed = el.dataset.seed || '';
      const n = Math.max(seed ? 1 : 0, Math.min(TREE_SLOTS, Number($(el, '#pk-n').value) || 0));
      const f = Math.max(1, Math.min(TREE_SLOTS, Number($(el, '#pk-f').value) || 1));
      S = await pkBuild(n, f, Math.floor(Math.random() * f), seed);
      if (root.Bailee.ui.emit) root.Bailee.ui.emit('bailee:published', { root: hex(S.net), seeded: !!seed });
      const period = wmValue(el, 'pk-p');
      out.innerHTML = `
        <div class="cols">
          <div class="panel chain">
            <h3>Published on chain</h3>
            ${row('Period', esc(period))}
            ${row('Network root', `<code>${esc(hex(S.net))}</code>`, 'mono')}
          </div>
          <div class="panel local">
            <h3>Held only by the firm</h3>
            ${row('Your communications', String(n))}
            ${row('Your firm root', `<code>${esc(short(hex(S.ours), 16))}</code>`, 'mono')}
            ${row('Other firms in the tree', String(f - 1))}
            ${row('Your position', `#${S.ourFirm + 1} of ${f} \u2014 unknowable from outside`)}
            ${row('Tree shape', `${TREE_SLOTS} fixed slots, depth ${TREE_DEPTH} \u2014 the rest are random dummies`)}
          </div>
        </div>
        <hr>
        <h3>Prove one document was in it</h3>
        <p>Evidence the holder may choose to use, without evidence that can be used against them.
        The firm reveals a path only when it wants to.</p>
        <div class="inline">
          <div class="field"><label>Document</label>
            <select id="pk-leaf">${S.docs.map((d, i) => `<option value="${i}">#${i + 1} \u2014 ${esc(d.label)}</option>`).join('')}</select></div>
          <button class="btn ghost" id="pk-prove"${n ? '' : ' disabled'}>Show inclusion proof</button>
        </div>
        <div id="pk-proof"></div>`;
      wireCopy(out);
      $(el, '#pk-prove').addEventListener('click', prove);
    }

    async function prove() {
      // An empty period has a root but nothing to prove into it.
      if (!S.docs.length) {
        $(el, '#pk-proof').innerHTML = '<p class="muted">This period held nothing. The root still'
          + ' published; there is simply no document to prove.</p>';
        return;
      }
      const i = Number($(el, '#pk-leaf').value);
      const proof = await documentProof(S.docTree, i, S.netTree, S.ourFirm);
      const leaf = S.docs[i].commitment;
      const r = await verifyDocumentProof(leaf, proof, S.net);
      const steps = [...proof.leafProof.map((p) => ['document tree', p]), ...proof.firmProof.map((p) => ['network tree', p])];
      $(el, '#pk-proof').innerHTML = `
        <div class="verdict ${r.ok ? 'pass' : 'fail'}"><span class="mark">${r.ok ? '\u2713' : '\u2717'}</span>
          <span><strong>${r.ok ? 'Included in the published root' : 'Not in the published root'}</strong>
          document \u2192 firm root ${r.inFirm ? '<span class="ok">\u2713</span>' : '<span class="bad">\u2717</span>'}
          &middot; firm root \u2192 network root ${r.inNetwork ? '<span class="ok">\u2713</span>' : '<span class="bad">\u2717</span>'}
          &middot; ${steps.length} sibling hashes, ${(steps.length * 32)} bytes of proof
          &mdash; the same ${steps.length} for every document in every period
          </span></div>
        ${monoBlock(hex(leaf), 'Commitment being proved')}
        <div class="tree">
          ${steps.map(([which, p], k) => `<div class="lvl">
            <span class="node self">step ${k + 1}</span>
            <span class="node">${esc(which)}</span>
            <span class="node path">${esc(p.side)} sibling ${esc(short(hex(p.hash), 8))}</span>
          </div>`).join('')}
          <div class="lvl"><span class="node path">= ${esc(short(hex(S.net), 12))} (published)</span></div>
        </div>
        <p class="note">${PROOF_DISCLOSURE}</p>`;
      wireCopy($(el, '#pk-proof'));
    }

    $(el, '#pk-go').addEventListener('click', build);
    build();
  }

  mount('protocol', pkRender);

  root.Bailee.protocol = { TREE_DEPTH, TREE_SLOTS, PROOF_DISCLOSURE, periodTree, documentProof, verifyDocumentProof };
})(typeof globalThis !== 'undefined' ? globalThis : this);
