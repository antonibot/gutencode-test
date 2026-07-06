#!/usr/bin/env node
// check-baseline.js — offline integrity check. No Python, no dependencies (node:crypto/fs/path only).
//
// Recomputes the sha256 of every baseline file in .gutencode/manifest.json and compares it to the printed baseline.
// This is the "is this the code I was given, unmodified?" proof — the one check you do NOT need Python for. PROTECTED
// files (the verifiers + the contract) can never be acknowledged. Exit 0 = baseline intact, 1 = tampered.
//
//   node check-baseline.js
//
// For the FULL behavioral proof (your test suite, route contract, error envelope, restart durability) run your own
// suite (`node --test`) and, when you have Python, `python verify.py` (it checks all three languages at once).
// Acknowledge intentional edits to a shipped file in .gutencode/accepted.json so this report stays meaningful.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const HERE = __dirname;
const PACK = path.join(HERE, '.gutencode');
// the verification layer — modifying any of these is never acknowledgeable (you cannot weaken the check in silence)
const PROTECTED = new Set(['verify.py', 'check-baseline.js', 'check-baseline.go']);
const sha256 = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

function main() {
  if (!fs.existsSync(PACK)) {
    console.log('[FAIL] .gutencode/ missing — this tree is not a verifiable export');
    return 1;
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(PACK, 'manifest.json'), 'utf8'));
  const contractPath = path.join(PACK, 'contract.json');
  let accepted = new Set();
  const accPath = path.join(PACK, 'accepted.json');
  if (fs.existsSync(accPath)) accepted = new Set(JSON.parse(fs.readFileSync(accPath, 'utf8')));

  const missing = [], drifted = [], protectedHits = [];
  for (const rel of Object.keys(manifest.files).sort()) {
    const p = path.join(HERE, ...rel.split('/'));
    if (!fs.existsSync(p)) {
      (PROTECTED.has(rel) ? protectedHits : missing).push(rel);
    } else if (sha256(p) !== manifest.files[rel]) {
      if (PROTECTED.has(rel)) protectedHits.push(rel);
      else if (!accepted.has(rel)) drifted.push(rel);
    }
  }
  if (manifest.contract_sha256 && sha256(contractPath) !== manifest.contract_sha256) {
    protectedHits.push('.gutencode/contract.json');
  }

  const fail = protectedHits.length || missing.length || drifted.length;
  const n = Object.keys(manifest.files).length;
  if (protectedHits.length)
    console.log(`[FAIL] the verification layer was modified — never acknowledgeable: ${JSON.stringify(protectedHits.slice(0, 5))}`);
  if (missing.length)
    console.log(`[FAIL] ${missing.length} baseline file(s) MISSING: ${JSON.stringify(missing.slice(0, 5))}`);
  if (drifted.length)
    console.log(`[FAIL] ${drifted.length} baseline file(s) modified — acknowledge in .gutencode/accepted.json: ${JSON.stringify(drifted.slice(0, 5))}`);
  if (!fail) console.log(`[ OK ] baseline intact — ${n} files match .gutencode/manifest.json`);
  console.log(`==== BASELINE: ${fail ? 'TAMPERED' : 'INTACT'} ====  (full proof: \`node --test\` + \`python verify.py\`)`);
  return fail ? 1 : 0;
}

process.exit(main());
