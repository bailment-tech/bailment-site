// Dynamic chat UX layer for Bailment workplace.  ->  Bailee.chatUx
//
// Brings the "live, streaming" feel of the Evatt chat surface to the Bailment
// workplace: message bubbles fade + slide in as they appear, and a typing
// indicator is shown while a message is being composed/streamed. Purely
// presentational; it never changes message data or the R1-R6 rules.
(function (root) {
  'use strict';
  root.Bailee = root.Bailee || {};
  const UI = root.Bailee.ui || {};
  const esc = UI.esc || ((s) => String(s == null ? '' : s));

  const style = document.createElement('style');
  style.textContent = `
    .wp-msg { opacity: 0; transform: translateY(6px); transition: opacity .22s ease, transform .22s ease; }
    .wp-msg.wp-msg--in { opacity: 1; transform: translateY(0); }
    .wp-typing { display: inline-flex; gap: 4px; align-items: center; padding: 6px 10px; }
    .wp-typing span { width: 6px; height: 6px; border-radius: 50%; background: currentColor; opacity: .4; animation: wp-blink 1.2s infinite; }
    .wp-typing span:nth-child(2) { animation-delay: .2s; }
    .wp-typing span:nth-child(3) { animation-delay: .4s; }
    @keyframes wp-blink { 0%, 80%, 100% { opacity: .3; } 40% { opacity: 1; } }
  `;
  document.head.appendChild(style);

  function reveal(node) {
    if (!node || node.classList.contains('wp-msg--in')) return;
    requestAnimationFrame(() => node.classList.add('wp-msg--in'));
  }

  function scan(rootEl) {
    (rootEl || document).querySelectorAll('.wp-msg').forEach(reveal);
  }

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.classList && n.classList.contains('wp-msg')) reveal(n);
        scan(n);
      }
    }
  });

  function init() {
    scan(document);
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  root.Bailee.chatUx = { reveal, scan };
})(window);
