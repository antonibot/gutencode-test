// The Postgres store DRIVER — the same six-method interface as the SQLite driver, behind the store facade
// (store.js). Selected by store_factory when DATABASE_URL names Postgres (Supabase or any). `pg` (node-postgres) is
// an OPTIONAL dependency (optionalDependencies in package.json) imported LAZILY via dynamic import, so the default
// install stays zero-dep and the SQLite path never loads it.
//
// The dangerous translation (identical to the python/go drivers): SQLite's `do()` takes a whole-DB write lock
// with BEGIN IMMEDIATE *before* the read, serializing the insert-first/claim case (the exactly-once claim seam —
// single-use codes, the money path). Postgres has no IMMEDIATE, and `SELECT … FOR UPDATE` locks NOTHING on a
// not-yet-existing row — so it cannot serialize a claim. The correct analog is `pg_advisory_xact_lock(<key>)` held
// for the whole transaction: exactly one transaction holds the per-key lock at a time, so read-decide-write is
// serialized even when the row is absent. The lock key is PG's own `hashtextextended` over a LENGTH-PREFIXED
// `(ns,k)` encoding (64-bit, injective — distinct keys never collide).
//
// Values are stored as `text` — byte-identical to the SQLite/facade JSON, so the cross-language raw-value contract
// holds (jsonb would CANONICALIZE — reorder keys / strip whitespace — diverging the stored bytes ×backend). The
// `seq bigserial` gives `values()` a stable insertion order (SQLite's rowid has no PG equivalent).
//
// node specifics: the store surface is ASYNC, so this driver awaits pg naturally. A single pooled connection
// (`max: 1`) is the SAME single-connection model as go's SetMaxOpenConns(1) — and, with the synchronous `inDo`
// reentry guard (node is single-threaded and the do() callback is PURE+SYNC), a nested store call inside a do()
// callback throws at the guard BEFORE it can deadlock on the one held connection.

export function scrubDsn(url) {
  // Redact userinfo from a DSN for an error line — never echo the password. postgres://u:p@h → postgres://u:***@h.
  try {
    const i = url.indexOf('://');
    if (i < 0) return '<dsn>';
    const scheme = url.slice(0, i);
    const rest = url.slice(i + 3);
    const at = rest.indexOf('@');
    if (at < 0) return url;
    let user = rest.slice(0, at);
    const c = user.indexOf(':');
    if (c >= 0) user = user.slice(0, c);
    return `${scheme}://${user}:***@${rest.slice(at + 1)}`;
  } catch {
    return '<dsn>';
  }
}

// length-prefixed (ns,k) so the map to a lock string is INJECTIVE (distinct keys never share a lock); PG's
// hashtextextended turns it into the 64-bit advisory-lock key. A deployment picks ONE language, so node's
// (utf16-unit) length prefix only needs to be injective within node — and namespaces are ASCII constants.
function lockArg(ns, key) {
  return `${ns.length}:${ns}${key}`;
}

export function newPostgresDriver(url) {
  // SCRUB-ON-DELETE HONESTY (a real security-property difference, made LOUD not silent): SQLite's global
  // `PRAGMA secure_delete=ON` zeroes a freed row's bytes on every DELETE — secrets_vault DESTROY relies on it for a
  // true revocation. Postgres has NO row-level equivalent: a DELETE (and even an overwrite — MVCC keeps the old
  // tuple) leaves plaintext in dead heap tuples until VACUUM, and in any logical replica / backup. At-rest
  // encryption answers a DIFFERENT threat (disk theft), not a live read. Selecting Postgres SILENTLY downgrades the
  // scrub for EVERY domain — refuse to start until the operator ACKNOWLEDGES it. Crypto-shred is the real upgrade.
  // This check is SYNCHRONOUS and runs at getDriver()/import, so the app refuses to boot without the ack.
  if (!(process.env.SECURE_DELETE_ACK || '').trim()) {
    throw new Error(
      'the Postgres backend cannot scrub deleted bytes on delete (SQLite\'s secure_delete has no Postgres '
      + 'equivalent) — deleted data may persist in dead tuples until VACUUM and in replicas/backups. Set '
      + 'SECURE_DELETE_ACK=1 to acknowledge and proceed, or use the SQLite backend for the scrub guarantee.');
  }

  let pool = null;       // pg.Pool, created on first use (dynamic import keeps pg optional)
  let readyPromise = null;
  let inDo = false;      // reentry guard: a nested store call inside a do() callback throws (exact — node single-threaded, fn sync)

  function guard() {
    if (inDo) {
      throw new Error('store call inside a storeDo() callback: fn must be pure (no storeGet/storePut/storeValues/'
        + 'storeDelete/nextId/storeDo) — it gets the current value and returns the next');
    }
  }

  // ensureReady — memoized one-time: dynamic-import pg, build the single-connection pool, create the schema. Lazy
  // so the SQLite default never imports pg and a connect error surfaces loudly on first use (the ack check already
  // failed loud at construction). The CREATE TABLE statements tolerate the PG cold-start race (parity with python/go).
  function ensureReady() {
    if (!readyPromise) {
      readyPromise = (async () => {
        let pg;
        try {
          pg = (await import('pg')).default;
        } catch {
          throw new Error('DATABASE_URL names Postgres but the `pg` package is not installed — run '
            + '`npm install pg` (it is an optional dependency), or unset DATABASE_URL to use SQLite.');
        }
        pool = new pg.Pool({ connectionString: url, max: 1 });
        try {
          await initTable('CREATE TABLE IF NOT EXISTS _kv (ns text, k text, v text, seq bigserial, PRIMARY KEY (ns, k))');
          await initTable('CREATE TABLE IF NOT EXISTS _seq (name text PRIMARY KEY, n bigint)');
        } catch (e) {
          throw new Error(`could not connect to DATABASE_URL (${scrubDsn(url)}): ${(e && e.message) || e}`);
        }
      })();
    }
    return readyPromise;
  }

  async function initTable(ddl) {
    // `CREATE TABLE IF NOT EXISTS` is NOT atomic in Postgres: two cold-starting workers can both pass the existence
    // check then collide ("relation already exists" / "duplicate key" / "tuple concurrently updated"). The table DOES
    // exist after the race — treat it as success, not an error (parity with go's mustExecPG / python's _init_table).
    try {
      await pool.query(ddl);
    } catch (e) {
      const m = String((e && e.message) || e).toLowerCase();
      if (!m.includes('already exists') && !m.includes('duplicate key') && !m.includes('concurrently')) throw e;
    }
  }

  // RAW interface: get/values return raw json strings (or undefined); put/do take raw json; the facade marshals.
  return {
    get db() { return pool; }, // the raw backend handle (surface parity; white-box uses only; null until first use)

    async get(ns, key) {
      guard();
      await ensureReady();
      const r = await pool.query('SELECT v FROM _kv WHERE ns = $1 AND k = $2', [ns, key]);
      return r.rows.length ? r.rows[0].v : undefined;
    },

    async put(ns, key, raw) {
      guard();
      await ensureReady();
      await pool.query('INSERT INTO _kv (ns, k, v) VALUES ($1, $2, $3) ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v',
        [ns, key, raw]);
    },

    async values(ns) {
      guard();
      await ensureReady();
      const r = await pool.query('SELECT v FROM _kv WHERE ns = $1 ORDER BY seq', [ns]);
      return r.rows.map((row) => row.v);
    },

    async delete(ns, key) {
      guard();
      await ensureReady();
      await pool.query('DELETE FROM _kv WHERE ns = $1 AND k = $2', [ns, key]);
    },

    async nextId(name) {
      guard();
      await ensureReady();
      const r = await pool.query(
        'INSERT INTO _seq (name, n) VALUES ($1, 1) ON CONFLICT (name) DO UPDATE SET n = _seq.n + 1 RETURNING n', [name]);
      return Number(r.rows[0].n);
    },

    // do — raw read-modify-write serialized across PROCESSES by the per-key transaction-scoped advisory lock (the
    // claim-safe analog of BEGIN IMMEDIATE). fn(rawCur | undefined) -> [rawNext | undefined, result]. fn is PURE+SYNC,
    // so the inDo flag is exact and the single held connection never deadlocks on a nested call (the guard throws first).
    async do(ns, key, fn) {
      guard();
      await ensureReady();
      const client = await pool.connect(); // the one pooled connection; concurrent do()s on it serialize (go's max-1 model)
      try {
        await client.query('BEGIN');
        // SOLE serializer of read-decide-write for the claim case (FOR UPDATE locks nothing on an absent row); held
        // for the whole transaction, so exactly one txn claims an absent key.
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockArg(ns, key)]);
        const r = await client.query('SELECT v FROM _kv WHERE ns = $1 AND k = $2', [ns, key]);
        const rawCur = r.rows.length ? r.rows[0].v : undefined;
        inDo = true;
        let rawNext, result;
        try {
          [rawNext, result] = fn(rawCur); // PURE + SYNC: no await between inDo=true and inDo=false → one atomic block
        } finally {
          inDo = false;
        }
        if (rawNext !== undefined) {
          await client.query('INSERT INTO _kv (ns, k, v) VALUES ($1, $2, $3) ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v',
            [ns, key, rawNext]);
        }
        await client.query('COMMIT');
        return result;
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* the transaction never opened */ }
        throw err;
      } finally {
        client.release();
      }
    },
  };
}
