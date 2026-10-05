// HTTP surface for the lock-voting audit service.
//
//   GET  /healthz                 liveness probe
//   POST /v1/audits               submit (or replay) a captured track
//   GET  /v1/audits/:audit_id     retrieve the recorded verdict for an id
//
// A re-submission with the same audit_id and identical semantics replays the
// original verdict (HTTP 200, replayed: true). A same-id submission with
// different content is an explicit conflict (HTTP 409).
import http from 'node:http';
import { URL } from 'node:url';
import {
  PayloadError, adjudicate, fingerprint, validateRequest,
} from './audit.js';
import { VerdictStore } from './store.js';

const MAX_BODY_BYTES = 1_048_576;

export function createApp(store = new VerdictStore()) {
  const send = (res, status, payload) => {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
    });
    res.end(body);
  };

  const readJson = (req) => new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new PayloadError(`request body exceeds ${MAX_BODY_BYTES} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (raw.length === 0) {
        reject(new PayloadError('request body is empty'));
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new PayloadError('request body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const path = url.pathname;

    try {
      if (req.method === 'GET' && (path === '/healthz' || path === '/health')) {
        send(res, 200, { status: 'ok', service: 'pollux-lock-audit', time: new Date().toISOString() });
        return;
      }

      if (req.method === 'POST' && path === '/v1/audits') {
        const body = await readJson(req);
        const parsed = validateRequest(body);
        const fp = fingerprint(parsed);
        const lookup = store.check(parsed.auditId, fp);
        if (lookup.status === 'replay') {
          send(res, 200, { replayed: true, ...lookup.record.verdict });
          return;
        }
        if (lookup.status === 'conflict') {
          send(res, 409, {
            error: 'AUDIT_ID_CONFLICT',
            message: 'a track with this audit_id was already recorded with different content',
            audit_id: parsed.auditId,
            original_fingerprint: lookup.record.fingerprint,
            received_fingerprint: fp,
          });
          return;
        }
        const verdict = adjudicate(parsed);
        store.save(parsed.auditId, fp, verdict);
        send(res, 200, { replayed: false, ...verdict });
        return;
      }

      const getMatch = path.match(/^\/v1\/audits\/([A-Za-z0-9_.\-~]{1,128})$/);
      if (req.method === 'GET' && getMatch) {
        const id = decodeURIComponent(getMatch[1]);
        const record = store.get(id);
        if (!record) {
          send(res, 404, { error: 'NOT_FOUND', message: 'no verdict recorded for this audit_id', audit_id: id });
          return;
        }
        send(res, 200, { replayed: true, ...record.verdict });
        return;
      }

      if (req.method === 'GET' && path === '/') {
        send(res, 200, {
          service: 'pollux-lock-audit',
          endpoints: {
            health: 'GET /healthz',
            submit: 'POST /v1/audits',
            verdict: 'GET /v1/audits/:audit_id',
          },
        });
        return;
      }

      send(res, 404, { error: 'NOT_FOUND', message: `unknown route ${req.method} ${path}` });
    } catch (err) {
      if (err instanceof PayloadError) {
        send(res, 400, { error: 'INVALID_SUBMISSION', message: err.message });
        return;
      }
      send(res, 500, { error: 'INTERNAL_ERROR', message: String(err && err.message || err) });
    }
  });
}

export function startServer({ port = Number(process.env.PORT) || 8080, host = process.env.HOST || '0.0.0.0' } = {}) {
  const server = createApp();
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT) || 8080;
  const host = process.env.HOST || '0.0.0.0';
  startServer({ port, host }).then((server) => {
    const address = server.address();
    console.log(`pollux-lock-audit listening on http://${host}:${address.port}`);
  });
}
