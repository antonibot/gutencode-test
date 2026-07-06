import { sendJSON } from '../core/runtime.js';

export function healthCheck(req, res) {
  // read-scope: public — liveness probe, returns only {status}, no domain state.
  sendJSON(res, 200, { status: 'ok' });
}
