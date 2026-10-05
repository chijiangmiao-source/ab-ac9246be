// One-shot verification: lock-rule unit tests followed by HTTP/API smoke
// against a real server on an ephemeral port. Exits non-zero on first failure.
import assert from 'node:assert/strict';
import process from 'node:process';
import { createApp } from '../src/server.js';
import { adjudicate, validateRequest } from '../src/audit.js';
import {
  b64, fakeHash, generateValidators, buildHealthyChain,
  makeProposal, makeAttestation, makeVote, submission,
} from './helpers.js';

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  ✓ ${name}`);
  } catch (err) {
    results.push({ name, ok: false, err });
    console.log(`  ✗ ${name}`);
    console.log(String(err && err.stack || err).split('\n').map((l) => `      ${l}`).join('\n'));
  }
}

function run(sub) {
  return adjudicate(validateRequest(sub));
}

// ---------------------------------------------------------------------------
async function lockRuleTests() {
  console.log('Lock-rule unit tests');

  await test('n=7 healthy chain seals the first block via three consecutive 2f+1 proofs', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-7');
    const aid = 'audit-happy-7';
    const { events, blocks } = buildHealthyChain(aid, vals, genesis, 3);
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.verdict, 'COMMITTED');
    assert.equal(r.threshold, 5);
    assert.equal(r.frozen_at, null);
    assert.equal(r.quorum_certificates.length, 3);
    for (const qc of r.quorum_certificates) {
      assert.equal(new Set(qc.signers).size, 5, 'each proof has 2f+1 distinct signers');
    }
    assert.equal(r.committed_blocks.length, 1);
    const c = r.committed_blocks[0];
    assert.equal(c.height, 1);
    assert.equal(c.block, blocks[1]);
    assert.deepEqual(c.proof_chain_views, [1, 2, 3]);
    assert.equal(new Set(c.proof_signers[1]).size, 5);
    // Every validator reports a lock history starting at genesis view 0.
    for (const v of vals) {
      const hist = r.lock_changes[v.pub];
      assert.ok(Array.isArray(hist) && hist.length >= 1);
      assert.deepEqual(
        [hist[0].locked_view, hist[0].locked_block],
        [0, genesis],
      );
    }
    // Proposer of B2 personally observed the view-1 proof carried in its proposal.
    const proposerB2 = vals[1].pub; // (h-1) % 7 = 1
    assert.ok(r.lock_changes[proposerB2].some(
      (e) => e.locked_view === 1 && e.locked_block === blocks[1],
    ));
  });

  await test('n=4 threshold is 3 and a four-proof chain commits B1 and B2', () => {
    const vals = generateValidators(4);
    const genesis = fakeHash('genesis-4');
    const aid = 'audit-happy-4';
    const { events, blocks } = buildHealthyChain(
      aid, vals, genesis, 4, { attesters: 3, votersEachView: 2 },
    );
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.verdict, 'COMMITTED');
    assert.equal(r.threshold, 3);
    assert.equal(r.committed_blocks.map((c) => c.block).join(','),
      [blocks[1], blocks[2]].join(','));
  });

  await test('proposal citing a proof that never formed freezes at that event', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x1');
    const aid = 'audit-no-proof';
    const b1 = fakeHash('b1');
    const ghost = fakeHash('ghost-qc');
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: ghost }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.verdict, 'REJECTED');
    assert.equal(r.frozen_at.event_index, 0);
    assert.equal(r.frozen_at.reason, 'proof_not_formed');
    assert.deepEqual(r.committed_blocks, []);
  });

  await test('dangling parent freezes at the earliest offending event', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x2');
    const aid = 'audit-dangle';
    const orphan = fakeHash('orphan');
    const b2 = fakeHash('b2');
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: orphan, parent: fakeHash('missing'), qc: 'GENESIS' }),
      // later, healthy-looking events that must never be evaluated:
      makeProposal(aid, vals[1], { height: 2, block: b2, parent: orphan, qc: orphan }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'dangling_parent');
    assert.equal(r.frozen_at.event_index, 0);
    assert.equal(r.events_processed, 0);
  });

  await test('proposal parent must match the block sealed by the cited proof', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x3');
    const aid = 'audit-mismatch';
    const b1 = fakeHash('b1');
    const other = fakeHash('other-height1');
    const b2 = fakeHash('b2');
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      makeProposal(aid, vals[0], { height: 1, block: other, parent: genesis, qc: 'GENESIS' }),
      // B2 claims parent `other` while citing the QC formed over b1:
      makeProposal(aid, vals[1], { height: 2, block: b2, parent: other, qc: b1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'parent_qc_mismatch');
    assert.equal(r.frozen_at.event_index, 7);
  });

  await test('invalid signatures on each event type freeze with invalid_signature', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x4');
    const aid = 'audit-badsig';
    const b1 = fakeHash('b1-badsig');
    for (const [idx, ev] of [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }, { badSig: true }),
    ].entries()) {
      const r = run(submission(`${aid}-${idx}`, vals, genesis, [ev]));
      assert.equal(r.frozen_at.reason, 'invalid_signature');
    }
    // attestation / vote bad signatures on top of a real B1:
    const good = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
    ];
    const rAtt = run(submission(`${aid}-att`, vals, genesis, [
      ...good,
      makeAttestation(aid, vals[1], { height: 1, block: b1 }, { badSig: true }),
    ]));
    assert.equal(rAtt.frozen_at.reason, 'invalid_signature');
    const rVote = run(submission(`${aid}-vote`, vals, genesis, [
      ...good,
      makeVote(aid, vals[1], { height: 1, block: b1, parent: genesis, proofView: 0 }, { badSig: true }),
    ]));
    assert.equal(rVote.frozen_at.reason, 'invalid_signature');
  });

  await test('duplicate validator identity in the submission is rejected', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x5');
    assert.throws(() => validateRequest({
      audit_id: 'dup-id',
      validators: [vals[0].pub, vals[0].pub, vals[1].pub, vals[2].pub],
      genesis: { hash: genesis },
      events: [],
    }), /duplicate validator identity/);
  });

  await test('validator counts other than 4 or 7 are rejected', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x6');
    assert.throws(() => validateRequest({
      audit_id: 'bad-count', validators: vals.slice(0, 5).map((v) => v.pub),
      genesis: { hash: genesis }, events: [],
    }), /4 or 7/);
  });

  await test('double vote in the same view freezes and suppresses later conclusions', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x7');
    const aid = 'audit-dblvote';
    const { events, blocks } = buildHealthyChain(aid, vals, genesis, 3);
    // vals[6] votes B1 twice for conflicting blocks. A second sibling at
    // height 1 is proposed first (legal, both extend genesis under GENESIS).
    const b1prime = fakeHash('b1-sibling');
    const doubleVote = makeVote(aid, vals[6], {
      height: 1, block: blocks[1], parent: genesis, proofView: 0,
    });
    const conflictingVote = makeVote(aid, vals[6], {
      height: 1, block: b1prime, parent: genesis, proofView: 0,
    });
    const tampered = [
      events[0], // the healthy B1 proposal must precede votes for B1
      makeProposal(aid, vals[6], { height: 1, block: b1prime, parent: genesis, qc: 'GENESIS' }),
      doubleVote,
      conflictingVote, // earliest safety violation -> freeze here (index 3)
      ...events.slice(1),
    ];
    const r = run(submission(aid, vals, genesis, tampered));
    assert.equal(r.verdict, 'REJECTED');
    assert.equal(r.frozen_at.reason, 'double_vote');
    assert.equal(r.frozen_at.event_index, 3);
    assert.deepEqual(r.committed_blocks, []);
    assert.equal(r.events_processed, 3);
  });

  await test('unsafe vote for a stale sibling that does not extend the lock is frozen', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x8');
    const aid = 'audit-unsafe';
    const b1 = fakeHash('u-b1');
    const b2 = fakeHash('u-b2');
    const b2sib = fakeHash('u-b2-sibling');
    const b3 = fakeHash('u-b3');
    const v = vals[5]; // not among attesters 0..4
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      makeProposal(aid, vals[1], { height: 2, block: b2, parent: b1, qc: b1 }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 2, block: b2 })),
      // stale sibling proposal at height 2, also justified by QC(b1): legal
      makeProposal(aid, vals[2], { height: 2, block: b2sib, parent: b1, qc: b1 }),
      // v proposes B3 citing QC(b2): v personally observes the view-2 proof
      // and locks on b2.
      makeProposal(aid, v, { height: 3, block: b3, parent: b2, qc: b2 }),
      // v now votes for the stale sibling: proof view 1 is not strictly higher
      // than v's view-2 lock, and the sibling does not extend b2.
      makeVote(aid, v, { height: 2, block: b2sib, parent: b1, proofView: 1 }),
      // anything after must be ignored:
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 3, block: b3 })),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'unsafe_vote');
    assert.equal(r.frozen_at.event_index, 14);
    assert.deepEqual(r.committed_blocks, []);
    // lock history shows v reached view 2 before the rejected vote
    const top = r.lock_changes[v.pub].at(-1);
    assert.equal(top.locked_view, 2);
    assert.equal(top.locked_block, b2);
  });

  await test('vote is legal when candidate extends the locked block at an equal proof view', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x9');
    const aid = 'audit-extends';
    const b1 = fakeHash('e-b1');
    const b2a = fakeHash('e-b2a');
    const b2b = fakeHash('e-b2b');
    const v = vals[5];
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      // v proposes B2a citing QC(b1): v locks b1 at view 1.
      makeProposal(aid, v, { height: 2, block: b2a, parent: b1, qc: b1 }),
      makeProposal(aid, vals[2], { height: 2, block: b2b, parent: b1, qc: b1 }),
      // v votes B2b, a sibling of B2a: equal proof view 1, but B2b extends the
      // locked block b1, so this is safe.
      makeVote(aid, v, { height: 2, block: b2b, parent: b1, proofView: 1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    // No safety violation; the short track simply cannot seal three blocks.
    assert.equal(r.frozen_at, null);
    assert.equal(r.reason, 'insufficient_quorum_chain');
    assert.equal(r.events_processed, events.length);
  });

  await test('strictly higher proof on a conflicting branch unlocks the vote', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x10');
    const aid = 'audit-unlock';
    const b1 = fakeHash('n-b1');
    const b2 = fakeHash('n-b2');
    const b3 = fakeHash('n-b3');
    const v = vals[5];
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      makeProposal(aid, vals[1], { height: 2, block: b2, parent: b1, qc: b1 }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 2, block: b2 })),
      // v first locks b2 at view 2 via a B3 proposal
      makeProposal(aid, v, { height: 3, block: b3, parent: b2, qc: b2 }),
      // v votes B2 at view 2: proof view 1 is below the lock view, but B2 is
      // the locked block itself (extends itself) -> legal.
      makeVote(aid, v, { height: 2, block: b2, parent: b1, proofView: 1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at, null);
    assert.equal(r.reason, 'insufficient_quorum_chain');
  });

  await test('below-threshold attestations never form a proof', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x11');
    const aid = 'audit-thin';
    const b1 = fakeHash('t-b1');
    const b2 = fakeHash('t-b2');
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      // only f=2 attestations, one short of 2f+1=5
      makeAttestation(aid, vals[0], { height: 1, block: b1 }),
      makeAttestation(aid, vals[1], { height: 1, block: b1 }),
      makeProposal(aid, vals[1], { height: 2, block: b2, parent: b1, qc: b1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'proof_not_formed');
    assert.equal(r.frozen_at.event_index, 3);
    assert.deepEqual(r.quorum_certificates, []);
  });

  await test('track without three consecutive proofs ends REJECTED, not committed', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x12');
    const aid = 'audit-short';
    const { events } = buildHealthyChain(aid, vals, genesis, 2);
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.verdict, 'REJECTED');
    assert.equal(r.frozen_at, null);
    assert.equal(r.reason, 'insufficient_quorum_chain');
  });

  await test('more than 64 events is refused up front', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x13');
    const b1 = fakeHash('big-b1');
    const events = [];
    for (let k = 0; k < 65; k += 1) {
      events.push(makeAttestation('audit-too-many', vals[k % 7], { height: 1, block: b1 }));
    }
    assert.throws(() => validateRequest({
      audit_id: 'audit-too-many',
      validators: vals.map((x) => x.pub),
      genesis: { hash: genesis },
      events,
    }), /at most 64/);
  });

  await test('byte-identical repeated events are idempotent replays', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x14');
    const aid = 'audit-idem';
    const { events, blocks } = buildHealthyChain(aid, vals, genesis, 3);
    const dup = [events[0], events[0], ...events.slice(1)];
    const r = run(submission(aid, vals, genesis, dup));
    assert.equal(r.verdict, 'COMMITTED');
    assert.equal(r.committed_blocks[0].block, blocks[1]);
  });

  await test('a validator cannot attest for two blocks in the same view', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x15');
    const aid = 'audit-dblatt';
    const b1 = fakeHash('a-b1');
    const b1b = fakeHash('a-b1b');
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      makeProposal(aid, vals[1], { height: 1, block: b1b, parent: genesis, qc: 'GENESIS' }),
      makeAttestation(aid, vals[3], { height: 1, block: b1 }),
      makeAttestation(aid, vals[3], { height: 1, block: b1b }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'double_attestation');
    assert.equal(r.frozen_at.event_index, 3);
  });

  await test('adjudication is deterministic for the same submission', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x16');
    const aid = 'audit-determinism';
    const sub = submission(aid, vals, genesis,
      buildHealthyChain(aid, vals, genesis, 3).events);
    const r1 = run(sub);
    const r2 = run(sub);
    assert.deepEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)));
  });

  await test('attestations themselves advance the attester lock and block stale votes', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x18');
    const aid = 'audit-att-lock';
    const b1 = fakeHash('l-b1');
    const b2 = fakeHash('l-b2');
    const v = vals[0];
    const events = [
      makeProposal(aid, vals[6], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      makeProposal(aid, vals[6], { height: 2, block: b2, parent: b1, qc: b1 }),
      ...[0, 1, 2, 3, 4].map((k) => makeAttestation(aid, vals[k], { height: 2, block: b2 })),
      // v attested B2, thereby personally observing QC(B1): its lock must be
      // B1 at view 1. Voting B2 (which extends B1) remains safe.
      makeVote(aid, v, { height: 2, block: b2, parent: b1, proofView: 1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at, null);
    assert.ok(r.lock_changes[v.pub].some((e) => e.locked_view === 1 && e.locked_block === b1));
  });

  await test('two conflicting branches at one view can never both reach 2f+1', () => {
    const vals = generateValidators(7);
    const genesis = fakeHash('genesis-x17');
    const aid = 'audit-two-chains';
    const b1 = fakeHash('c-b1');
    const b1x = fakeHash('c-b1x');
    const b2 = fakeHash('c-b2');
    // Split the 7 validators 4 vs 3 across the siblings: with f=2, neither
    // side reaches 5, so no threshold proof can form on either chain.
    const events = [
      makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }),
      makeProposal(aid, vals[4], { height: 1, block: b1x, parent: genesis, qc: 'GENESIS' }),
      ...[0, 1, 2, 3].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1 })),
      ...[4, 5, 6].map((k) => makeAttestation(aid, vals[k], { height: 1, block: b1x })),
      // any extension citing either would-be proof must be rejected:
      makeProposal(aid, vals[0], { height: 2, block: b2, parent: b1, qc: b1 }),
    ];
    const r = run(submission(aid, vals, genesis, events));
    assert.equal(r.frozen_at.reason, 'proof_not_formed');
    assert.deepEqual(r.quorum_certificates, []);
    assert.deepEqual(r.committed_blocks, []);
  });
}

// ---------------------------------------------------------------------------
async function httpSmoke() {
  console.log('HTTP / API smoke tests');
  // AUDIT_BASE_URL targets an already-running container (Compose smoke);
  // otherwise spin up the app in-process on an ephemeral port.
  const external = process.env.AUDIT_BASE_URL;
  let server = null;
  let base;
  if (external) {
    base = external.replace(/\/$/, '');
    const deadline = Date.now() + 15000;
    for (;;) {
      try {
        const res = await fetch(base + '/healthz');
        if (res.ok) break;
      } catch { /* service not ready */ }
      if (Date.now() > deadline) throw new Error(`audit service at ${base} never became ready`);
      await new Promise((r) => setTimeout(r, 300));
    }
  } else {
    server = createApp();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  }

  const call = async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try { json = await res.json(); } catch { /* non-json */ }
    return { status: res.status, json };
  };

  try {
    await test('GET /healthz returns ok', async () => {
      const { status, json } = await call('GET', '/healthz');
      assert.equal(status, 200);
      assert.equal(json.status, 'ok');
    });

    const vals = generateValidators(7);
    const genesis = fakeHash('smoke-genesis');

    await test('POST a valid track returns COMMITTED with proof signers', async () => {
      const aid = 'smoke-commit';
      const body = submission(aid, vals, genesis,
        buildHealthyChain(aid, vals, genesis, 3).events);
      const { status, json } = await call('POST', '/v1/audits', body);
      assert.equal(status, 200);
      assert.equal(json.verdict, 'COMMITTED');
      assert.equal(json.replayed, false);
      assert.equal(json.committed_blocks.length, 1);
      assert.equal(new Set(json.quorum_certificates[0].signers).size, 5);
    });

    await test('POST a bad-signature track is REJECTED and frozen at index 0', async () => {
      const aid = 'smoke-reject';
      const b1 = fakeHash('smoke-bad-b1');
      const body = submission(aid, vals, genesis, [
        makeProposal(aid, vals[0], { height: 1, block: b1, parent: genesis, qc: 'GENESIS' }, { badSig: true }),
      ]);
      const { status, json } = await call('POST', '/v1/audits', body);
      assert.equal(status, 200);
      assert.equal(json.verdict, 'REJECTED');
      assert.equal(json.frozen_at.reason, 'invalid_signature');
    });

    await test('same audit_id with same semantics replays the original verdict', async () => {
      const aid = 'smoke-replay';
      const body = submission(aid, vals, genesis,
        buildHealthyChain(aid, vals, genesis, 3).events);
      const first = await call('POST', '/v1/audits', body);
      assert.equal(first.json.replayed, false);
      const second = await call('POST', '/v1/audits', JSON.parse(JSON.stringify(body)));
      assert.equal(second.status, 200);
      assert.equal(second.json.replayed, true);
      assert.equal(second.json.verdict, first.json.verdict);
      assert.deepEqual(second.json.committed_blocks, first.json.committed_blocks);
      const got = await call('GET', `/v1/audits/${aid}`);
      assert.equal(got.status, 200);
      assert.equal(got.json.verdict, 'COMMITTED');
    });

    await test('same audit_id with different content is an explicit 409 conflict', async () => {
      const aid = 'smoke-conflict';
      const body = submission(aid, vals, genesis,
        buildHealthyChain(aid, vals, genesis, 3).events);
      await call('POST', '/v1/audits', body);
      const altered = JSON.parse(JSON.stringify(body));
      altered.genesis.hash = fakeHash('different-genesis');
      const { status, json } = await call('POST', '/v1/audits', altered);
      assert.equal(status, 409);
      assert.equal(json.error, 'AUDIT_ID_CONFLICT');
      assert.notEqual(json.original_fingerprint, json.received_fingerprint);
    });

    await test('malformed submissions get 400', async () => {
      const r1 = await call('POST', '/v1/audits', { nope: true });
      assert.equal(r1.status, 400);
      const res = await fetch(base + '/v1/audits', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json',
      });
      assert.equal(res.status, 400);
    });

    await test('unknown verdict id is 404 and unknown route is 404', async () => {
      assert.equal((await call('GET', '/v1/audits/no-such-id')).status, 404);
      assert.equal((await call('GET', '/nope')).status, 404);
    });
  } finally {
    if (server) server.close();
  }
}

async function main() {
  await lockRuleTests();
  await httpSmoke();
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) {
    console.error(`FAILED: ${failed.map((f) => f.name).join('; ')}`);
    process.exit(1);
  }
  console.log('ALL VERIFICATION CHECKS PASSED');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
