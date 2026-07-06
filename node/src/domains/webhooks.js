// webhooks — Standard-Webhooks signing (outbound webhookSend) + verification with REPLAY-DEDUP (inbound webhookVerify).
// Calls the CENTRAL signing part (never re-inlines HMAC); the msg seq, the sent log, and the inbound
// seen-set live in the durable store seam (same names as the python/go impls); the clock comes from testNow
// (a `now` param counts only under APP_TEST_CLOCK=1).
//
// DANGEROUS PROPERTY: delivery integrity at a trust boundary — a forgery, a REPLAY, or a silently-dropped ROTATED
// delivery is takeover-class. (1) MULTI-SECRET ROTATION: webhookSend signs with EVERY active secret (space-joined);
// webhookVerify accepts a delivery matching ANY active secret. (2) INBOUND REPLAY-DEDUP (exactly-once): a same-id 2nd
// verify inside the window is flagged a DUPLICATE so the consumer skips it.
//
// TWO routes, TWO auth models: webhookSend is ADMIN-ONLY (requireAdmin) — signing with the SERVER secret means an
// open route is signature forgery; no token 401, a non-admin 403, resolved BEFORE the payload check (×3). webhookVerify
// is intentionally PUBLIC (see its `mutation-auth: public` declaration).
import { isStrictInt, nextId, problem, requireAdmin, sendJSON, storeDo, storeGet, storePut, testNow } from '../core/runtime.js';
import { scopedKey } from '../parts/digest.js';
import { signV1, verifyV1 } from '../parts/signing.js';

// active signing secrets — NEWLINE-separated list, each ASCII-trimmed (empties dropped). UNSET falls back to the demo
// default; a present-but-BLANK value resolves to NO active secret -> deny (never the placeholder). The trim is the ASCII
// whitespace bytes ONLY (NOT .trim()'s set, which strips U+FEFF/BOM while py/go strip U+0085/NEL) — a contaminated secret
// would otherwise key to a different HMAC per runtime; ASCII-only is byte-identical ×3. Rotation.
const WH_TRIM = /^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g;
const whRawSecrets = 'WEBHOOK_SECRETS' in process.env ? process.env.WEBHOOK_SECRETS : 'whsec_demo_change_me';
const WH_SECRETS = whRawSecrets.split('\n').map((s) => s.replace(WH_TRIM, '')).filter((s) => s);
const WH_TOLERANCE = 300; // seconds; replay window
const VERIFY_ROUTE = 'POST /webhooks/verify'; // the dedup-slot discriminator — route + the matched-secret label

export async function webhookSend(req, res) {
  // ADMIN-ONLY: authn -> authz FIRST, so a no-token caller is 401 and a non-admin is 403 BEFORE the payload
  // check — never the "payload required" 422, identical ×3 with python/go.
  if ((await requireAdmin(req, res)) === null) return;
  const payload = new URL(req.url, 'http://localhost').searchParams.get('payload') || '';
  if (!payload) return problem(res, 422, 'payload required');
  const timestamp = testNow(req);
  const id = `msg_${await nextId('webhooks_msg')}`;
  await storePut('webhooks_sent', id, { id, timestamp, payload });
  // sign with ALL active secrets (rotation): a receiver on any active secret accepts
  const signature = WH_SECRETS.map((s) => signV1(s, id, timestamp, payload)).join(' ');
  sendJSON(res, 201, { id, timestamp, payload, signature });
}

export async function webhookVerify(req, res, params, body) {
  // mutation-auth: public — INTENTIONALLY unauthenticated (a stateless + dedup HMAC check; no session caller). The
  // PUBLIC {valid} shape leaks no reason (a reason-oracle is a signing oracle — SW spec). The dedup WRITE is BEHIND
  // the signature gate (only a validly-signed event reaches it), so a no-secret caller cannot pump the seen-set.
  if (!body || typeof body.id !== 'string' || !isStrictInt(body, 'timestamp')
      || typeof body.payload !== 'string' || typeof body.signature !== 'string') {
    return problem(res, 422, 'invalid body');
  }
  const now = testNow(req);
  let verified = false;
  for (let i = 0; i < WH_SECRETS.length; i += 1) { // multi-secret: accept if ANY active secret verifies (rotation)
    if (verifyV1(WH_SECRETS[i], body.id, body.timestamp, body.payload, body.signature, now, WH_TOLERANCE)) {
      verified = true;
      break;
    }
  }
  if (!verified) return sendJSON(res, 200, { valid: false, duplicate: false }); // forged/stale -> nothing to dedup
  // INBOUND REPLAY-DEDUP, scoped to the EVENT IDENTITY (route + event id) — NOT which secret matched. The matched
  // secret is CALLER-CONTROLLABLE: a sender broadcasts one candidate per active secret, so presenting only another
  // secret's candidate would flip a per-secret slot and replay the SAME event as new during a rotation. Any active
  // secret authenticates the same event, so the secret has no role in the dedup key. Fast-path a lockless get; reserve
  // the write lock (storeDo) for a genuinely-new id; storeDo re-checks atomically (concurrent first-race -> one writer).
  const slot = scopedKey(VERIFY_ROUTE, 'wh', body.id);
  if ((await storeGet('webhooks_seen', slot)) !== undefined) return sendJSON(res, 200, { valid: true, duplicate: true });
  let duplicate = false;
  await storeDo('webhooks_seen', slot, (cur) => {
    if (cur !== undefined) { duplicate = true; return [undefined, null]; } // concurrent first won -> this is the duplicate
    return [{ id: body.id, ts: body.timestamp }, null];                    // claim it (first delivery)
  });
  sendJSON(res, 200, { valid: true, duplicate });
}
