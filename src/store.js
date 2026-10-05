// In-memory verdict store: same audit_id + same semantics replays the original
// verdict; same audit_id with different content is an explicit CONFLICT.
const DEFAULT_TTL_MS = 60 * 60 * 1000;

export class VerdictStore {
  constructor(ttlMs = DEFAULT_TTL_MS) {
    this.ttlMs = ttlMs;
    this.records = new Map(); // auditId -> {fingerprint, verdict, createdAt}
  }

  _expire(id, now) {
    const rec = this.records.get(id);
    if (rec && now - rec.createdAt > this.ttlMs) {
      this.records.delete(id);
      return null;
    }
    return rec;
  }

  // Returns {status: 'replay'|'conflict'|'new', record?}
  check(auditId, fp, now = Date.now()) {
    const rec = this._expire(auditId, now);
    if (!rec) return { status: 'new' };
    if (rec.fingerprint === fp) {
      return { status: 'replay', record: rec };
    }
    return { status: 'conflict', record: rec };
  }

  get(auditId, now = Date.now()) {
    return this._expire(auditId, now);
  }

  save(auditId, fp, verdict, now = Date.now()) {
    this.records.set(auditId, { fingerprint: fp, verdict, createdAt: now });
  }

  get size() {
    return this.records.size;
  }
}
