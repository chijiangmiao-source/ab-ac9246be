// Core safety-audit engine: replays a captured restricted-view lock-voting
// track and derives a commit / reject verdict. No third-party dependencies.
//
// Observation model
// -----------------
// The capture is an ordered, restricted view of events. A threshold proof
// (quorum certificate, QC) is *formed* at the capture index where attestations
// from 2f+1 distinct validators for one block are first present. A validator
// personally observes the proof cited by an event they sign:
//   - a valid proposal carries the QC that justifies its parent,
//   - a valid vote is cast over the QC justifying its candidate.
// Each validator therefore maintains its lock on the block sealed by the
// highest-view QC it has personally observed.
import crypto from 'node:crypto';

export const PROTOCOL_TAG = 'POLLUX-LOCK-AUDIT/v1';
export const GENESIS_QC = 'GENESIS';
export const MAX_EVENTS = 64;

export class PayloadError extends Error {}

// ---------------------------------------------------------------------------
// Deterministic decoding
// ---------------------------------------------------------------------------

export function decodeB64(value, what) {
  if (typeof value !== 'string') throw new PayloadError(`${what} must be a base64 string`);
  const urlSafe = /[-_]/.test(value);
  const clean = urlSafe
    ? value.replace(/-/g, '+').replace(/_/g, '/')
    : value;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
    throw new PayloadError(`${what} is not valid base64`);
  }
  const padded = clean.padEnd(clean.length + ((4 - (clean.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64');
}

function decodeKey(value) {
  const raw = decodeB64(value, 'validator public key');
  if (raw.length !== 32) throw new PayloadError('validator public key must be 32 bytes (Ed25519)');
  return raw;
}

function decodeHash(value, what) {
  const raw = decodeB64(value, what);
  if (raw.length !== 32) throw new PayloadError(`${what} must be 32 bytes`);
  return value;
}

// ---------------------------------------------------------------------------
// Canonical signing payloads (stable UTF-8, newline separated)
// ---------------------------------------------------------------------------

export function canonicalProposalMessage(auditId, ev) {
  return [PROTOCOL_TAG, auditId, ev.validator, 'proposal',
    String(ev.height), ev.block, ev.parent, ev.qc].join('\n');
}

export function canonicalAttestationMessage(auditId, ev) {
  return [PROTOCOL_TAG, auditId, ev.validator, 'attestation',
    String(ev.height), ev.block].join('\n');
}

export function canonicalVoteMessage(auditId, ev, proofView) {
  return [PROTOCOL_TAG, auditId, ev.validator, 'vote',
    String(ev.height), ev.block, ev.parent, String(proofView)].join('\n');
}

export function verifySignature(publicKeyB64, message, signatureB64) {
  let sig;
  try {
    sig = decodeB64(signatureB64, 'signature');
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      decodeB64(publicKeyB64, 'public key'),
    ]);
    const keyObj = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(message, 'utf8'), keyObj, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Submission validation
// ---------------------------------------------------------------------------

export function validateRequest(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new PayloadError('request body must be a JSON object');
  }
  const auditId = body.audit_id;
  if (typeof auditId !== 'string' || auditId.length === 0 || auditId.length > 128) {
    throw new PayloadError('audit_id must be a non-empty string of at most 128 characters');
  }

  if (!Array.isArray(body.validators)) throw new PayloadError('validators must be an array');
  if (body.validators.length !== 4 && body.validators.length !== 7) {
    throw new PayloadError('exactly 4 or 7 validator public keys are required');
  }
  const validators = [];
  const seen = new Set();
  for (const v of body.validators) {
    const canonical = decodeKey(v).toString('base64');
    if (seen.has(canonical)) throw new PayloadError('duplicate validator identity in submission');
    seen.add(canonical);
    validators.push(canonical);
  }

  if (body.genesis === null || typeof body.genesis !== 'object') {
    throw new PayloadError('genesis block object is required');
  }
  const genesisHash = decodeHash(body.genesis.hash, 'genesis.hash');

  if (!Array.isArray(body.events)) throw new PayloadError('events must be an array');
  if (body.events.length > MAX_EVENTS) {
    throw new PayloadError(`at most ${MAX_EVENTS} events are accepted`);
  }

  const known = new Set(validators);
  const events = body.events.map((ev, idx) => {
    const at = `events[${idx}]`;
    if (ev === null || typeof ev !== 'object' || Array.isArray(ev)) {
      throw new PayloadError(`${at} must be an object`);
    }
    if (!known.has(decodeKey(ev.validator).toString('base64'))) {
      throw new PayloadError(`${at}.validator is not in the validator set`);
    }
    const validator = decodeKey(ev.validator).toString('base64');
    if (typeof ev.signature !== 'string') throw new PayloadError(`${at}.signature is required`);
    const signature = decodeB64(ev.signature, `${at}.signature`)
      .toString('base64');
    if (!Number.isSafeInteger(ev.height) || ev.height <= 0) {
      throw new PayloadError(`${at}.height must be a positive safe integer`);
    }
    const block = decodeHash(ev.block, `${at}.block`);
    if (block === genesisHash) throw new PayloadError(`${at}.block collides with the genesis hash`);

    const out = {
      type: ev.type, validator, signature, block, height: ev.height, _index: idx,
    };
    if (ev.type === 'proposal') {
      out.parent = decodeHash(ev.parent, `${at}.parent`);
      if (typeof ev.qc !== 'string') throw new PayloadError(`${at}.qc is required`);
      out.qc = ev.qc === GENESIS_QC ? GENESIS_QC : decodeHash(ev.qc, `${at}.qc`);
    } else if (ev.type === 'vote') {
      out.parent = decodeHash(ev.parent, `${at}.parent`);
    } else if (ev.type !== 'attestation') {
      throw new PayloadError(`${at}.type must be proposal, attestation or vote`);
    }
    return out;
  });

  return { auditId, validators, genesisHash, events };
}

// Stable semantic fingerprint for stable-id replay / conflict detection.
export function fingerprint(req) {
  const canonical = JSON.stringify({
    validators: req.validators,
    genesis: req.genesisHash,
    events: req.events.map((e) => {
      const out = {
        type: e.type, validator: e.validator, height: e.height,
        block: e.block, signature: e.signature,
      };
      if (e.parent !== undefined) out.parent = e.parent;
      if (e.qc !== undefined) out.qc = e.qc;
      return out;
    }),
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Track replay
// ---------------------------------------------------------------------------

export function adjudicate(req) {
  const { auditId, validators, genesisHash, events } = req;
  const n = validators.length;
  const f = Math.floor((n - 1) / 3);
  const threshold = 2 * f + 1;

  // block hash -> {height, parent, qc}
  const blocks = new Map();
  blocks.set(genesisHash, { height: 0, parent: null, qc: GENESIS_QC });
  // block hash -> {view, signers: Map<pub,index>, formedAt}
  const qcs = new Map();
  const proposed = new Map(); // block hash -> proposal event
  const attested = new Map(); // pub!height -> block
  const voted = new Map(); // pub!height -> block

  const lock = new Map(); // pub -> {view, block}
  const lockChanges = new Map(); // pub -> [entries]
  for (const pub of validators) {
    lock.set(pub, { view: 0, block: genesisHash });
    lockChanges.set(pub, [{
      event_index: null,
      reason: 'genesis',
      highest_qc_view: 0,
      locked_view: 0,
      locked_block: genesisHash,
    }]);
  }

  const result = {
    audit_id: auditId,
    verdict: 'REJECTED',
    reason: 'frozen',
    validator_count: n,
    max_faulty: f,
    threshold,
    genesis: genesisHash,
    validators,
    events_processed: 0,
    total_events: events.length,
    frozen_at: null,
    quorum_certificates: [],
    committed_blocks: [],
    lock_changes: {},
  };

  const isAncestor = (descendantHash, ancestorHash) => {
    let cur = descendantHash;
    const guard = new Set();
    while (cur && !guard.has(cur)) {
      if (cur === ancestorHash) return true;
      guard.add(cur);
      const b = blocks.get(cur);
      if (!b) return false;
      cur = b.parent;
    }
    return false;
  };

  const raiseLock = (pub, view, blockHash, eventIndex, reason) => {
    const top = lock.get(pub);
    if (view > top.view) {
      lock.set(pub, { view, block: blockHash });
      lockChanges.get(pub).push({
        event_index: eventIndex,
        reason,
        highest_qc_view: view,
        locked_view: view,
        locked_block: blockHash,
      });
      return true;
    }
    return false;
  };

  const onQcFormed = (qc, eventIndex) => {
    const entry = {
      view: qc.view,
      block: qc.block,
      signers: [...qc.signers.keys()],
      formed_at_event: eventIndex,
    };
    result.quorum_certificates.push(entry);

    // Three-chain rule: QC(B_h) over QC(B_{h-1}) over QC(B_{h-2}) seals B_{h-2}.
    if (qc.view >= 3) {
      const bMid = blocks.get(qc.block).parent;
      const qcMid = bMid ? qcs.get(bMid) : null;
      if (qcMid && qcMid.formedAt !== null && qcMid.view === qc.view - 1) {
        const bLow = blocks.get(bMid).parent;
        const qcLow = bLow ? qcs.get(bLow) : null;
        if (qcLow && qcLow.formedAt !== null && qcLow.view === qc.view - 2) {
          if (!result.committed_blocks.some((c) => c.block === qcLow.block)) {
            result.committed_blocks.push({
              height: qc.view - 2,
              block: qcLow.block,
              committed_at_event: eventIndex,
              proof_chain_views: [qc.view - 2, qc.view - 1, qc.view],
              proof_signers: {
                [qcLow.view]: [...qcLow.signers.keys()],
                [qcMid.view]: [...qcMid.signers.keys()],
                [qc.view]: [...qc.signers.keys()],
              },
            });
          }
        }
      }
    }
  };

  const freeze = (index, reason, detail) => {
    result.frozen_at = { event_index: index, reason, ...(detail ? { detail } : {}) };
    result.events_processed = index;
  };

  // An exact byte-for-byte repeat of an already accepted observation is an
  // idempotent replay; it never advances state. Only conflicting duplicates
  // (same validator + view, different block) freeze the track.
  const seenEvents = new Set();
  const dedupe = (ev) => {
    const key = JSON.stringify([
      ev.type, ev.validator, ev.height, ev.block, ev.parent ?? null,
      ev.qc ?? null, ev.signature,
    ]);
    if (seenEvents.has(key)) return true;
    seenEvents.add(key);
    return false;
  };

  let frozen = false;
  for (const ev of events) {
    const i = ev._index;
    if (dedupe(ev)) {
      result.events_processed = i + 1;
      continue;
    }

    if (ev.type === 'proposal') {
      if (proposed.has(ev.block)) {
        const prev = proposed.get(ev.block);
        if (prev.height !== ev.height || prev.parent !== ev.parent
          || prev.qc !== ev.qc || prev.validator !== ev.validator) {
          freeze(i, 'conflicting_proposal_for_block',
            'the same block hash was already proposed with different fields');
          frozen = true;
          break;
        }
        result.events_processed = i + 1;
        continue;
      }
      if (!blocks.has(ev.parent)) {
        freeze(i, 'dangling_parent', 'parent block is not known on this track');
        frozen = true;
        break;
      }
      const parent = blocks.get(ev.parent);
      if (parent.height + 1 !== ev.height) {
        freeze(i, 'parent_height_mismatch',
          `proposal height ${ev.height} does not extend parent at height ${parent.height}`);
        frozen = true;
        break;
      }
      let proofView;
      if (ev.qc === GENESIS_QC) {
        if (ev.parent !== genesisHash) {
          freeze(i, 'parent_qc_mismatch', 'GENESIS proof may only justify a child of genesis');
          frozen = true;
          break;
        }
        proofView = 0;
      } else {
        const qc = qcs.get(ev.qc);
        if (!qc || qc.formedAt === null) {
          freeze(i, 'proof_not_formed',
            'proposal cites a threshold proof that has not reached 2f+1 distinct signers');
          frozen = true;
          break;
        }
        if (qc.block !== ev.parent || qc.view !== parent.height) {
          freeze(i, 'parent_qc_mismatch',
            'parent block must be exactly the block sealed by the cited proof');
          frozen = true;
          break;
        }
        proofView = qc.view;
      }
      if (!verifySignature(ev.validator, canonicalProposalMessage(auditId, ev), ev.signature)) {
        freeze(i, 'invalid_signature', 'proposal signature failed Ed25519 verification');
        frozen = true;
        break;
      }
      blocks.set(ev.block, { height: ev.height, parent: ev.parent, qc: ev.qc });
      proposed.set(ev.block, ev);
      // The proposer has personally observed the proof carried by their proposal.
      raiseLock(ev.validator, proofView, ev.parent, i, 'higher_quorum_observed_in_proposal');
    } else if (ev.type === 'attestation') {
      const key = `${ev.validator}!${ev.height}`;
      if (attested.has(key)) {
        freeze(i, 'double_attestation',
          attested.get(key) === ev.block
            ? 'identical attestation already recorded'
            : 'a validator attested twice in the same view');
        frozen = true;
        break;
      }
      const target = blocks.get(ev.block);
      if (!target || target.height !== ev.height) {
        freeze(i, 'unknown_block', 'attestation targets a block that has not been proposed at that height');
        frozen = true;
        break;
      }
      if (!verifySignature(ev.validator, canonicalAttestationMessage(auditId, ev), ev.signature)) {
        freeze(i, 'invalid_signature', 'attestation signature failed Ed25519 verification');
        frozen = true;
        break;
      }
      attested.set(key, ev.block);
      // Attesting B_h presupposes observation of the proof justifying B_h.
      const attProofView = target.qc === GENESIS_QC ? 0 : qcs.get(target.qc)?.view;
      if (attProofView !== undefined && attProofView !== null) {
        raiseLock(ev.validator, attProofView, target.parent, i,
          'higher_quorum_observed_in_attestation');
      }
      let qc = qcs.get(ev.block);
      if (!qc) {
        qc = { view: ev.height, block: ev.block, signers: new Map(), formedAt: null };
        qcs.set(ev.block, qc);
      }
      qc.signers.set(ev.validator, i);
      if (qc.signers.size === threshold && qc.formedAt === null) {
        qc.formedAt = i;
        onQcFormed(qc, i);
      }
    } else {
      // vote
      const key = `${ev.validator}!${ev.height}`;
      if (voted.has(key)) {
        freeze(i, 'double_vote',
          voted.get(key) === ev.block
            ? 'identical vote already recorded'
            : 'a validator voted twice in the same view for conflicting blocks');
        frozen = true;
        break;
      }
      const candidate = blocks.get(ev.block);
      if (!candidate || candidate.height !== ev.height) {
        freeze(i, 'unknown_block', 'vote targets a block that has not been proposed at that height');
        frozen = true;
        break;
      }
      if (candidate.parent !== ev.parent) {
        freeze(i, 'parent_qc_mismatch', 'vote parent does not match the proposed candidate');
        frozen = true;
        break;
      }
      let proofView;
      if (candidate.qc === GENESIS_QC) {
        proofView = 0;
      } else {
        const qc = qcs.get(candidate.qc);
        if (!qc || qc.formedAt === null) {
          freeze(i, 'proof_not_formed', 'candidate proof has not reached threshold');
          frozen = true;
          break;
        }
        proofView = qc.view;
      }
      if (!verifySignature(ev.validator, canonicalVoteMessage(auditId, ev, proofView), ev.signature)) {
        freeze(i, 'invalid_signature', 'vote signature failed Ed25519 verification');
        frozen = true;
        break;
      }
      const top = lock.get(ev.validator);
      const extendsLock = isAncestor(ev.block, top.block);
      const higherProof = proofView > top.view;
      if (!extendsLock && !higherProof) {
        freeze(i, 'unsafe_vote',
          `candidate neither extends locked block ${top.block} at view ${top.view} `
          + `nor cites a strictly higher proof (candidate proof view ${proofView})`);
        frozen = true;
        break;
      }
      voted.set(key, ev.block);
      // Casting the vote demonstrates personal observation of the proof it cites.
      raiseLock(ev.validator, proofView, candidate.parent, i, 'higher_quorum_observed_in_vote');
    }
    result.events_processed = i + 1;
  }

  for (const pub of validators) result.lock_changes[pub] = lockChanges.get(pub);

  if (frozen) {
    // A frozen track yields no commit conclusion, even if proofs formed earlier.
    result.committed_blocks = [];
    result.reason = 'frozen';
  } else if (result.committed_blocks.length > 0) {
    result.verdict = 'COMMITTED';
    result.reason = 'three_chain_commit';
  } else {
    // The track was internally safe but never produced three consecutive
    // threshold proofs; frozen_at stays null because no event was invalid.
    result.reason = 'insufficient_quorum_chain';
    result.frozen_at = null;
  }
  return result;
}
