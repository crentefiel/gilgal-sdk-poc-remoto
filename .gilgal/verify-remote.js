#!/usr/bin/env node
// GILGAL SDK PoC - REMOTE verifier (runs as GitHub Action, server-side).
// Reads from the checked-out repo. NEVER trusts a stored "GATE=PASS" string.
const crypto = require('crypto');
const { execSync } = require('child_process');

function sh(cmd) {
  try { return execSync(cmd, { encoding: 'utf8' }); }
  catch (e) { return e.stdout ? e.stdout.toString() : ''; }
}
function canon(o) {
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  if (o && typeof o === 'object') {
    return '{' + Object.keys(o).sort().map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
  }
  return JSON.stringify(o);
}
function readAt(sha, p) {
  try { return execSync(`git show ${sha}:${p}`, { encoding: 'utf8' }); }
  catch (e) { return null; }
}
function val(prefix, A) {
  for (const a of A) { if (a.startsWith(prefix)) return a.slice(prefix.length); }
  return '';
}

function main() {
  const A = process.argv.slice(2);
  const cand = process.env.CANDIDATE_SHA || val('--candidate=', A);
  const stable = process.env.STABLE_SHA || val('--stable=', A);
  if (!cand || !stable) { console.log(JSON.stringify({ verdict: 'BLOCKED', reason: 'MISSING_SHAS' })); process.exit(1); }

  const ledgerRaw = readAt(cand, '.gilgal/ledger.json');
  const humanRaw = readAt(cand, '.gilgal/human-decisions.json');
  const budgetRaw = readAt(stable, '.gilgal/sentinel.json');
  const pubRaw = readAt(stable, '.gilgal/keys/human.pub');

  if (!ledgerRaw) { console.log(JSON.stringify({ verdict: 'BLOCKED', reason: 'NO_LEDGER' })); process.exit(1); }
  let ledger, human = null, budget = { maxInsertions: 0, maxDeletions: 0, maxFiles: 1e9 };
  try { ledger = JSON.parse(ledgerRaw); } catch (e) { console.log(JSON.stringify({ verdict: 'BLOCKED', reason: 'LEDGER_PARSE' })); process.exit(1); }
  if (humanRaw) { try { human = JSON.parse(humanRaw); } catch (e) {} }
  if (budgetRaw) { try { budget = JSON.parse(budgetRaw); } catch (e) {} }

  const pub = crypto.createPublicKey(pubRaw);
  let c = ledger.candidates.find(x => x.sha === cand);
  if (!c && ledger.candidates.length === 1) c = ledger.candidates[0];
  if (!c) { console.log(JSON.stringify({ verdict: 'BLOCKED', reason: 'CANDIDATE_NOT_IN_LEDGER' })); process.exit(1); }

  const fam = (ledger.families || []).find(f => f.name === c.family);
  const famState = fam ? fam.state : 'ACTIVE';

  let humanValid = false, humanPending = false;
  if (human && human.decisions) {
    for (const d of human.decisions) {
      if (d.candidateSha !== cand) continue; // staleness: must match promoted code commit
      const data = canon({ candidateSha: d.candidateSha, decision: d.decision, ts: d.ts });
      try {
        if (crypto.verify(null, Buffer.from(data), pub, Buffer.from(d.signature, 'base64'))) {
          if (d.decision === 'APPROVE') humanValid = true;
          if (d.decision === 'PENDING') humanPending = true;
        }
      } catch (e) {}
    }
  }

  const reasons = [];
  if (c.state === 'CRITICAL_FAIL') reasons.push('CRITICAL_FAIL');
  if (c.state === 'REJECTED') reasons.push('REJECTED');
  if (famState === 'EXHAUSTED') reasons.push('FAMILY_EXHAUSTED');
  if (!humanValid) reasons.push('NO_VALID_HUMAN_APPROVE');

  const diff = sh(`git diff --numstat ${stable} ${cand}`);
  let ins = 0, del = 0, files = 0;
  diff.split('\n').forEach(l => {
    if (!l.trim()) return;
    const p = l.split('\t');
    if (p[0] === '-') return;
    ins += +p[0] || 0; del += +p[1] || 0; files++;
  });
  if (ins > (budget.maxInsertions || 0)) reasons.push('BUDGET_INS');
  if (del > (budget.maxDeletions || 0)) reasons.push('BUDGET_DEL');
  if (files > (budget.maxFiles || 0)) reasons.push('BUDGET_FILES');

  const eligible = ledger.candidates.filter(x => {
    const f = (ledger.families || []).find(z => z.name === x.family);
    return x.state !== 'CRITICAL_FAIL' && x.state !== 'REJECTED' && (f ? f.state !== 'EXHAUSTED' : true);
  }).length;

  const out = { candidateSha: cand, stableSha: stable, verdict: null, reasons, eligibleCount: eligible, budgetIns: ins, budgetMax: budget.maxInsertions, humanValid };
  if (reasons.length) out.verdict = 'BLOCKED';
  else if (humanPending) out.verdict = 'PENDING';
  else out.verdict = 'PASS';

  console.log(JSON.stringify(out));
  if (out.verdict === 'PASS') process.exit(0);
  if (out.verdict === 'PENDING') process.exit(2);
  process.exit(1);
}
main();
