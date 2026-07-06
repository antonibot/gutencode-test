// Store model, namespaces, env knobs, the composite key, the atomic quota/count index, and the swappable provider
// (the storage idiom) for file_store. Handlers live in index.js; the byte/name validators in validate.js. Store
// namespaces + the DECISIONS match the python/go impls.
import { storeGet, storePut, storeDelete, storeDo } from '../../core/runtime.js';
import { envInt } from '../../parts/env_int.js';

const OBJECTS = 'file_store_objects'; // "<owner>\x1f<key>" -> {owner, key, content_b64, content_type, size, etag, created_at}
const INDEX = 'file_store_index';     // "<owner>" -> [{key, size}] codepoint-sorted (the quota + COUNT authority)
const SEP = '\x1f';                   // the unit separator — forbidden in user keys by the grammar, so the composite key can't be forged
export const okey = (owner, key) => owner + SEP + key; // owner FIRST: addressed by (owner, key), never the bare key

export const fsMaxBytes = () => envInt(process.env.FILE_STORE_MAX_BYTES, 524288, 1, 786000);
export const fsMaxKeys = () => envInt(process.env.FILE_STORE_MAX_KEYS, 1000, 1, 10000);
export const fsMaxTotalBytes = () => envInt(process.env.FILE_STORE_MAX_TOTAL_BYTES, 52428800, 1, 2 ** 40);

// the codepoint comparator — node's default .sort()/a<b is UTF-16 CODE-UNIT order ("😀" sorts BEFORE "｡"), which
// DIVERGES from python/go (codepoint order). Buffer.compare over utf-8 bytes IS codepoint order, matching x3.
const byKey = (a, b) => Buffer.compare(Buffer.from(a.key, 'utf8'), Buffer.from(b.key, 'utf8'));

// fsAdmit — ATOMIC quota/count admission through the index storeDo seam: the new-vs-existing decision AND the old
// size are read from `entries` INSIDE the callback (never a pre-do row read — a TOCTOU under concurrent replace
// that double-counts over a create-tear). The callback stays PURE + SYNCHRONOUS. Returns "ok"|"count"|"quota".
export async function fsAdmit(owner, key, size) {
  const mxKeys = fsMaxKeys();
  const mxTotal = fsMaxTotalBytes();
  return storeDo(INDEX, owner, (cur) => {
    const entries = cur ? cur.slice() : [];
    let total = 0;
    let old = -1;
    for (let i = 0; i < entries.length; i++) {
      total += entries[i].size; // total < MAX_KEYS*MAX_BYTES < 2^33 << 2^53 (safe accumulator x3)
      if (entries[i].key === key) old = i;
    }
    if (old >= 0) { // REPLACE: a delta on the existing reservation
      if (total - entries[old].size + size > mxTotal) return [undefined, 'quota'];
      entries[old] = { key, size };
      return [entries, 'ok'];
    }
    if (entries.length >= mxKeys) return [undefined, 'count']; // the file-COUNT cap (the partition-COUNT bound)
    if (total + size > mxTotal) return [undefined, 'quota']; // the total-BYTES quota
    // unbounded-safe: the per-owner entries list is bounded at FILE_STORE_MAX_KEYS by the reject-past-cap guard above (a create past the cap is a loud 422, never an eviction — dropping a user's file is data loss); bounding the COUNT bounds the per-owner key-space, each entry's bytes bounded by the 1024-byte key cap, so the index row is bounded by construction.
    entries.push({ key, size });
    entries.sort(byKey); // codepoint order x3 (NOT the default UTF-16 sort)
    return [entries, 'ok'];
  });
}

// fsRelease — remove the key's entry; resolves true iff it was present (the DELETE existence authority, so a phantom
// entry with no row is user-clearable), read-modified atomically through storeDo.
export async function fsRelease(owner, key) {
  return storeDo(INDEX, owner, (cur) => {
    const entries = cur || [];
    const kept = entries.filter((e) => e.key !== key);
    return kept.length === entries.length ? [undefined, false] : [kept, true];
  });
}

export async function fsIndexEntries(owner) {
  return (await storeGet(INDEX, owner)) || [];
}

// the provider seam (the storage idiom) — selected ONCE. 'store' = durable rows; 's3' = the FAIL-LOUD stub.
const durable = {
  name: 'store',
  async put(owner, key, row) { await storePut(OBJECTS, okey(owner, key), row); },
  async get(owner, key) { return storeGet(OBJECTS, okey(owner, key)); },
  async del(owner, key) { await storeDelete(OBJECTS, okey(owner, key)); },
};
// USER-SCOPED: a real adapter receives the AUTHENTICATED owner — namespace your bucket/prefix by it (an `<owner>/`
// key prefix), exactly as the durable provider composes `<owner>\x1f<key>`.
const s3fail = () => { throw new Error('the s3 provider is a customization stub - wire a real client here (or set FILE_STORE_PROVIDER=store)'); };
const s3 = { name: 's3', put: s3fail, get: s3fail, del: s3fail };

let instance = null;
export function provider() {
  if (instance === null) {
    if ((process.env.FILE_STORE_PROVIDER || 'store') === 's3') {
      if (!process.env.FILE_STORE_S3_BUCKET || !process.env.FILE_STORE_S3_ENDPOINT) {
        throw new Error('FILE_STORE_PROVIDER=s3 requires FILE_STORE_S3_BUCKET and FILE_STORE_S3_ENDPOINT'); // fail loud
      }
      instance = s3;
    } else {
      instance = durable;
    }
  }
  return instance;
}
