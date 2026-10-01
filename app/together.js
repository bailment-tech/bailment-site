// all-together.html: the four widgets, unchanged, opened one after another. Each widget
// announces the step it finished (Bailee.ui.emit); this page only listens, explains the
// next step in a pop-up, closes the finished part and opens the next one.
(function () {
  'use strict';
  if (typeof document === 'undefined') return;
  var UI = window.Bailee.ui;
  var part = function (n) { return document.getElementById('part-' + n); };
  var fold = function (n) { return document.getElementById('part-' + n + '-fold'); };
  var state = { commitment: '', digest: '', url: '', docs: [], done: false };

  function say(n, text) { part(n).querySelector('.together-status').textContent = text; }
  function openPart(n) {
    var f = fold(n);
    f.hidden = false;
    f.open = true;
    part(n).scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function closePart(n) { fold(n).open = false; }
  function put(scope, sel, value) {
    var box = scope.querySelector(sel);
    if (box && value) box.value = value;
  }

  // One pop-up, reused for every step. `next` runs on the button or on Escape. The dialog's
  // own `close` event is not used: headless Chromium did not fire it reliably.
  var pop = document.createElement('dialog');
  pop.className = 'wp-dialog together-pop';
  pop.setAttribute('aria-labelledby', 'together-pop-title');
  document.body.appendChild(pop);
  UI.wireCopy(pop);
  var next = null;
  function go() { var f = next; next = null; if (pop.open) pop.close(); if (f) f(); }
  pop.addEventListener('cancel', function (e) { e.preventDefault(); go(); });   // Escape
  function popup(title, bodyHtml, label, then, extraButtons) {
    next = then;
    pop.innerHTML = '<h2 id="together-pop-title">' + UI.esc(title) + '</h2>' + bodyHtml
      + '<div class="actions">' + (extraButtons || '')
      + '<button type="button" class="btn btn-primary" value="go">' + UI.esc(label) + '</button></div>';
    pop.querySelector('[value="go"]').addEventListener('click', go);
    if (pop.showModal) pop.showModal(); else go();
  }

  // Part 1 keeps every notarized document, by name, so the hash is always one click away.
  var list = document.getElementById('together-docs');
  UI.wireCopy(list);
  function remember(d) {
    for (var i = 0; i < state.docs.length; i++) if (state.docs[i].digest === d.digest) return null;
    var doc = { name: (d.title || 'Matter') + ' Doc ' + (state.docs.length + 1), digest: d.digest };
    state.docs.push(doc);
    var li = document.createElement('li');
    li.innerHTML = '<strong>' + UI.esc(doc.name) + '</strong> <code class="mono">' + UI.esc(doc.digest)
      + '</code> <button type="button" class="btn btn-ghost" data-copy="' + UI.esc(doc.digest) + '">Copy</button>';
    list.appendChild(li);
    list.hidden = false;
    return doc;
  }

  // The digest box in part 2 always holds the notarized hash: whatever is pasted or typed
  // over it is put back, so the certificate cannot be signed over the wrong document.
  var digestBox = function () { return part(2).querySelector('#ct-digest'); };
  document.addEventListener('input', function (e) {
    if (e.target === digestBox() && state.digest && e.target.value.trim() !== state.digest) {
      e.target.value = state.digest;
    }
  });

  // ---- Part 1 -> 2: any notarization, or any "Certify this ..." button in the thread.
  function goCertify() {
    closePart(1);
    say(1, 'Done. Your notarized documents are listed here.');
    say(2, 'Paste the hash into Document digest, check the citations and remove any false ones, then press Issue & sign certificate.');
    openPart(2);
    var box = digestBox();
    if (!box) return;
    box.value = state.digest;
    box.classList.add('together-glow');
    setTimeout(function () { box.focus(); box.select(); }, 400);
  }
  function toCertify(e) {
    var d = e.detail || {};
    if (!d.digest) return;
    state.digest = d.digest;
    if (d.commitment) state.commitment = d.commitment;
    var doc = remember(d);
    if (!doc) { goCertify(); return; }   // an already-listed hash skips the pop-up
    popup('Congrats, you have created a timestamp for the document!',
      '<p>Next step is to certify. You now have a SHA-256 hash for <strong>' + UI.esc(doc.name)
        + '</strong>. Paste it into Step 1, <em>Document digest</em>.</p>'
        + '<p><code class="mono together-hash">' + UI.esc(doc.digest) + '</code></p>',
      'Go to Certify', goCertify,
      '<button type="button" class="btn btn-ghost" data-copy="' + UI.esc(doc.digest) + '">Copy the hash</button>');
  }
  document.addEventListener('bailee:notarized', toCertify);
  document.addEventListener('bailee:certify', toCertify);

  // ---- Part 2 -> 3: the certificate is signed. Your record goes into the next batch.
  // The real verification URL carries the whole signed certificate and runs to hundreds of
  // characters. The demo hands the reader a 20-character stand-in and keeps the real one here.
  // ponytail: in-page alias only, it dies with the tab; a real short link needs a resolver service.
  var links = {};
  function shortLink(url) {
    var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', b = new Uint8Array(8), code = '';
    crypto.getRandomValues(b);
    for (var i = 0; i < 8; i++) code += abc[b[i] % abc.length];
    var link = 'bailee.link/' + code;   // 12 + 8 = 20 characters
    links[link] = url;
    return link;
  }
  var copyLink = function (link, label) {
    return '<button type="button" class="btn btn-ghost" data-copy="' + UI.esc(link) + '">' + (label || 'Copy') + '</button>';
  };

  function clearVerifier() {
    var v = document.getElementById('widget-verifier');
    var payload = v.querySelector('#ct-payload'), result = v.querySelector('#ct-result');
    if (payload) payload.value = '';
    if (result) result.innerHTML = '';
  }
  document.addEventListener('bailee:certified', function (e) {
    state.url = (e.detail || {}).url || '';
    state.link = shortLink(state.url);
    clearVerifier();
    // Part 2 shows the short link instead of the full certificate (hidden on this page by app.css).
    var box = document.getElementById('together-link') || document.createElement('div');
    box.id = 'together-link';
    box.className = 'together-link';
    box.innerHTML = '<span>Your verification link</span> <code>' + UI.esc(state.link) + '</code> '
      + copyLink(state.link) + '<span class="muted">Copy it. You need it in part 4 to verify.</span>';
    fold(2).parentNode.insertBefore(box, fold(2));   // outside the fold: still there when part 2 closes
    UI.wireCopy(box);
    say(2, 'Certified and signed. Your verification link is below.');
    popup('Your certificate is signed!',
      '<p>Copy your verification link now. You will need it in part 4 to verify.</p>'
        + '<p><code class="mono together-hash">' + UI.esc(state.link) + '</code></p>'
        + '<p>Next is part 3, <strong>Publish</strong>. Your notarized record joins this period’s batch, '
        + 'alongside every other firm’s records. The whole batch folds into one 32-byte root, and only '
        + 'that root goes on the blockchain. No names, no documents, no count.</p>',
      'Go to Publish', function () {
        closePart(2);
        openPart(3);
        buildPeriod();
      }, copyLink(state.link, 'Copy the link'));
  });

  // ---- Part 3: the root is already built when the reader arrives, with their record in it.
  // The Build button moves under the result, renamed Publish: pressing it is the step that publishes.
  function buildPeriod() {
    var proto = document.getElementById('widget-protocol');
    proto.dataset.seed = state.commitment || state.digest;
    var btn = proto.querySelector('#pk-go');
    if (btn && !btn.parentNode.classList.contains('together-bottom')) {
      var bottom = document.createElement('div');
      bottom.className = 'actions together-bottom';
      proto.appendChild(bottom);
      bottom.appendChild(btn);
      btn.textContent = 'Publish';               // on this page, pressing it IS publishing
      btn.classList.add('together-publish');
    }
    state.previewing = true;          // this build is the preview, not the publish
    if (btn) btn.click();
    say(3, 'Your record is communication #1 in this batch. Look it over, then press Publish at the bottom.');
  }

  // ---- Part 3 -> 4: the reader pressed Publish.
  document.addEventListener('bailee:published', function (e) {
    if (fold(3).hidden || !(e.detail || {}).seeded) return;
    if (state.previewing) { state.previewing = false; return; }
    say(3, 'Published. Your record is communication #1, and the chain holds only the root.');
    var v = document.getElementById('widget-verifier');
    var payload = v.querySelector('#ct-payload');
    if (payload) payload.placeholder = 'Paste your verification link, e.g. ' + state.link;
    put(v, '#ct-mydigest', state.digest);
    popup('Published to the chain!',
      '<p>Next is part 4, <strong>Verify</strong>. This is what a court does with your filing.</p>'
        + '<p>Paste your verification link into the verifier and press <em>Verify</em>. The court’s own '
        + 'browser checks the signature, the registry and all four claims. Nothing is uploaded.</p>'
        + '<p><code class="mono together-hash">' + UI.esc(state.link) + '</code></p>',
      'Go to Verify', function () {
        closePart(3);
        say(4, 'Paste your verification link, then press Verify.');
        openPart(4);
      }, copyLink(state.link, 'Copy the link'));
  });

  // Part 4: a pasted short link is swapped for the real certificate just before the
  // verifier reads the box (capture phase runs first), then put back so the reader sees
  // what they pasted. Anything else is left for the verifier to judge.
  document.getElementById('widget-verifier').addEventListener('click', function (e) {
    if (!e.target.closest || !e.target.closest('#ct-verify')) return;
    var box = this.querySelector('#ct-payload');
    var typed = box ? box.value.trim().replace(/^https?:\/\//, '') : '';
    state.pasted = typed;
    if (!links[typed]) return;
    box.value = links[typed];
    setTimeout(function () { box.value = typed; }, 0);
  }, true);

  // ---- Part 4: it verified. Everything closes, and the reader is told what they did.
  function backToCertify() {
    closePart(3);
    closePart(4);
    clearVerifier();
    state.done = false;
    say(4, 'Opens again when the new certificate is published.');
    say(2, 'Remove the false citations, check them again, then press Issue & sign certificate.');
    openPart(2);
    var cite = part(2).querySelector('#ct-cite');
    if (cite) setTimeout(function () { cite.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 300);
  }
  document.addEventListener('bailee:verified', function (e) {
    if (fold(4).hidden || state.done) return;
    if (!(e.detail || {}).ok) {
      // An older link from an earlier try: point at the newest one rather than send them back.
      if (state.pasted && state.pasted !== state.link && links[state.pasted]) {
        popup('That link is for an older certificate',
          '<p>You have issued a newer certificate since. Its link is below. Close this, and it goes '
            + 'into the verifier for you. Then press <em>Verify</em>.</p>'
            + '<p><code class="mono together-hash">' + UI.esc(state.link) + '</code></p>',
          'Use my newest link', function () {
            put(document.getElementById('widget-verifier'), '#ct-payload', state.link);
          });
        return;
      }
      say(4, 'This certificate does not verify. Go back to Certify and remove the false citations.');
      popup('This certificate does not verify',
        '<p>It still carries false citations, so the citation check fails. A court would reject it.</p>'
          + '<p>Go back to Certify. Press <em>Use the corrected passage</em> (or <em>Restart citation check</em> '
          + 'and remove the false citations yourself), check the citations again, then issue a new certificate.</p>',
        'Back to Certify', backToCertify);
      return;
    }
    state.done = true;
    say(4, 'Verified.');
    popup('Congratulations! You certified your work to the court!',
      '<p>Your work was timestamped, certified, published, and checked the way a court checks it. '
        + 'The certificate proves how the filing was made without revealing what is in it.</p>',
      'Done', function () {
        // Parts 1-3 close; part 4 stays open so the reader can read what the check did.
        [1, 2, 3].forEach(closePart);
        var lead = document.querySelector('.hero .lead');
        if (lead) lead.textContent = 'Congratulations! You certified your work to the court.';
        say(4, 'Verified. Read what the check did below, or start over.');
      });
  });

  // Part 4 always has a way out, whatever the verifier says.
  var bar = document.createElement('div');
  bar.className = 'actions together-bottom';
  bar.innerHTML = '<button type="button" class="btn btn-ghost" data-act="back">Back to Certify</button>'
    + '<button type="button" class="btn btn-primary together-publish" data-act="over">Start Over</button>';
  bar.querySelector('[data-act="back"]').addEventListener('click', backToCertify);
  bar.querySelector('[data-act="over"]').addEventListener('click', function () { location.reload(); });
  fold(4).appendChild(bar);
})();
