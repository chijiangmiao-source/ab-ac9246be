// Test helpers: Ed25519 key generation, canonical signing and track builders.
import crypto from 'node:crypto';
import {
  canonicalProposalMessage,
  canonicalAttestationMessage,
  canonicalVoteMessage,
} from '../src/audit.js';

export function b64(buf) {
  return Buffer.from(buf).toString('base64');
}

export function fakeHash(label) {
  return b64(crypto.createHash('sha256').update(label).digest());
}

export function generateValidators(count) {
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const der = publicKey.export({ type: 'spki', format: 'der' });
    const pubRaw = der.subarray(der.length - 32);
    out.push({
      index: i,
      pub: pubRaw.toString('base64'),
      publicKey,
      privateKey,
    });
  }
  return out;
}

function sign(priv, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), priv).toString('base64');
}

export function makeProposal(auditId, v, { height, block, parent, qc }, { badSig = false } = {}) {
  const ev = {
    type: 'proposal', validator: v.pub, height, block, parent, qc,
    signature: '',
  };
  ev.signature = badSig ? 'A'.repeat(86) + '=' : sign(v.privateKey, canonicalProposalMessage(auditId, ev));
  return ev;
}

export function makeAttestation(auditId, v, { height, block }, { badSig = false } = {}) {
  const ev = { type: 'attestation', validator: v.pub, height, block, signature: '' };
  ev.signature = badSig ? 'B'.repeat(86) + '=' : sign(v.privateKey, canonicalAttestationMessage(auditId, ev));
  return ev;
}

export function makeVote(auditId, v, { height, block, parent, proofView }, { badSig = false } = {}) {
  const ev = {
    type: 'vote', validator: v.pub, height, block, parent, signature: '',
  };
  ev.signature = badSig ? 'C'.repeat(86) + '=' : sign(v.privateKey, canonicalVoteMessage(auditId, ev, proofView));
  return ev;
}

// Builds a healthy single-chain track through `heights` heights with threshold
// attestations per block and a few votes per view. Returns pieces so tests can
// mutate the ordering.
export function buildHealthyChain(auditId, vals, genesis, heights, {
  attesters = 5, votersEachView = 3, proposerOffset = 0,
} = {}) {
  const events = [];
  const blocks = [genesis];
  for (let h = 1; h <= heights; h += 1) {
    const block = fakeHash(`${auditId}:B${h}:${Math.random()}`);
    blocks.push(block);
    const proposer = vals[(proposerOffset + h - 1) % vals.length];
    const qc = h === 1 ? 'GENESIS' : blocks[h - 1];
    events.push(makeProposal(auditId, proposer, {
      height: h, block, parent: blocks[h - 1], qc,
    }));
    for (let k = 0; k < votersEachView; k += 1) {
      const voter = vals[(proposerOffset + h + k) % vals.length];
      events.push(makeVote(auditId, voter, {
        height: h, block, parent: blocks[h - 1], proofView: h - 1,
      }));
    }
    for (let k = 0; k < attesters; k += 1) {
      events.push(makeAttestation(auditId, vals[k], { height: h, block }));
    }
  }
  return { events, blocks };
}

export function submission(auditId, vals, genesisHash, events) {
  return {
    audit_id: auditId,
    validators: vals.map((v) => v.pub),
    genesis: { hash: genesisHash },
    events,
  };
}
