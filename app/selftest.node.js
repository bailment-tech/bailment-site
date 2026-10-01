#!/usr/bin/env node
// Headless self-check: node app/selftest.node.js
// The same selftest.js the browser page runs. Classic scripts, so require() works.
require('./crypto.js');
require('./ui.js');
require('./notarize.js');
require('./certificate.js');
require('./attestation.js');
require('./protocol.js');
require('./selftest.js');

const G = '\x1b[32m', R = '\x1b[31m', D = '\x1b[2m', X = '\x1b[0m';
Bailee.selftest.run((name, ok, detail) => {
  if (ok === null) console.log(name ? (detail ? `  ${D}${name}: ${detail}${X}` : `\n${name}`) : '');
  else console.log(`  ${ok ? G + 'PASS' : R + 'FAIL'}${X} ${name}${detail ? D + '  \u2014 ' + detail + X : ''}`);
}).then((r) => process.exit(r.fail ? 1 : 0));
