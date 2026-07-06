// storage providers — the swappable seam (ports-and-adapters). Selection happens ONCE here (STORAGE_PROVIDER
// env), never at call sites. USER-SCOPED: the store key is the composite `<owner>\x1f<user-key>` (owner FIRST;
// the user key is well_formed — no control chars — so it can never contain the \x1f unit separator, and the
// composite key CANNOT be forged to reach another owner's object), and the stored row STAMPS its owner so the
// list filters on the authenticated owner and returns BARE keys. The public object shape ({key,content,size,etag})
// is unchanged — owner is internal. The 'store' provider keeps whole objects in the durable runtime store seam;
// the 's3' provider is the FAIL-LOUD customization stub: selecting it unconfigured (or unwired) throws -> a loud
// 500, never a silent black-hole store.
import { storeDelete, storeGet, storePut, storeValues } from '../../core/runtime.js';
import { digestHex } from '../../parts/digest.js';

const SEP = '\x1f'; // the unit separator — forbidden in user keys by well_formed, so the composite key can't be forged
const okey = (owner, key) => owner + SEP + key; // owner FIRST: addressed by (owner, key), never the user key alone

const durable = {
  async put(owner, key, content) {
    // size is BYTE length (utf-8) — go's len(string) counts bytes, so this is the x3-identical semantic
    const size = Buffer.byteLength(content, 'utf8');
    const etag = digestHex(content);
    const row = { owner, key, content, size, etag }; // owner stamped; the WHOLE object in ONE write
    await storePut('storage_objects', okey(owner, key), row); // under the owner-composed key
    return { key, provider: 'store', size, etag };
  },
  async get(owner, key) {
    const row = await storeGet('storage_objects', okey(owner, key));
    if (row === undefined) return undefined;
    return { key: row.key, content: row.content, size: row.size, etag: row.etag }; // owner stays internal
  },
  async del(owner, key) {
    const k = okey(owner, key);
    if ((await storeGet('storage_objects', k)) === undefined) return false;
    await storeDelete('storage_objects', k);
    return true;
  },
  async keys(owner) {
    // owner-filtered (on the stamped owner field), returned as BARE keys in a stable sorted order
    // unbounded-safe: the storageList route paginates this owner key set via the paginate part — keys() does the
    // raw storeValues scan but bounding happens one layer up at the route (the provider signature stays stable ×adapters)
    return (await storeValues('storage_objects')).filter((o) => o.owner === owner).map((o) => o.key).sort();
  },
};

const s3fail = () => {
  throw new Error('the s3 provider is a customization stub - wire a real client here (or set STORAGE_PROVIDER=store)');
};
// USER-SCOPED: each method receives the AUTHENTICATED owner first — namespace your bucket/prefix by it (e.g. an
// `<owner>/` key prefix), exactly as the durable provider composes `<owner>\x1f<key>`.
const s3 = { put: s3fail, get: s3fail, del: s3fail, keys: s3fail };

let instance = null;
export function provider() {
  if (instance === null) {
    if ((process.env.STORAGE_PROVIDER || 'store') === 's3') {
      if (!process.env.S3_BUCKET || !process.env.S3_ENDPOINT) {
        throw new Error('STORAGE_PROVIDER=s3 requires S3_BUCKET and S3_ENDPOINT'); // fail loud, never store nothing
      }
      instance = s3;
    } else {
      instance = durable;
    }
  }
  return instance;
}
