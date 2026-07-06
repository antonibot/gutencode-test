# FRONTEND.md — wiring a UI to this backend without the usual pain

This backend was built so the frontend can be **small, safe, and never blank on you.** This guide gives you the
five patterns that kill the failures every project hits. Examples are TypeScript (fetch) — the *patterns* apply
to any framework (React, Vue, Svelte, SwiftUI, native). **Coding with Claude Code, Cursor, or Copilot? Hand it this file.**

## The five failures this prevents
1. **Blank screen** — one un-wired or failed call throws in render and takes the whole page down.
2. **Scattered `fetch()`** — authentication, errors, retries re-implemented (differently) in 40 places.
3. **Unsafe or missing retries** — either none (flaky UX) or naive ones that double-submit a payment.
4. **Front↔back drift** — the backend changes a field; the UI finds out in production.
5. **Total failure on one error** — no loading/error/empty states, so anything less than the happy path breaks.

## 0 · Three things this backend already gives you (build on them)
1. **ONE error shape, everywhere.** Every error — every route, all three languages — is RFC 9457 problem+json:
   `{ "type", "title", "status", "detail" }` with `Content-Type: application/problem+json`. **You write ONE
   parser and ONE error type.** (Verified by the shipped `code/error-shape` check.)
2. **A machine-readable contract.** `.gutencode/contract.json` lists every route + its request/response shape +
   example bodies. **This is your source of truth for types** — mirror it (or generate from it) and the UI can't
   silently drift from the API.
3. **Idempotency-Key on writes.** Endpoints that accept an `Idempotency-Key` header dedup a repeated write by key
   — so a **retried POST is safe** (no double-create, no double-charge). This is what makes §3 possible. Check
   `.gutencode/contract.json` for which routes accept an `Idempotency-Key`.

   Plus: list responses are `{ results, next_cursor }` (cursor pagination); the session is a `Bearer` token; a `429`
   means rate-limited; a `404` (not a `403`) is how "not yours / doesn't exist" is returned (existence never
   leaks); `413` = body too large; `422` = validation. CORS is opened with `CORS_ALLOWED_ORIGINS` on the backend.

---

## 1 · Centralize every call — one client module (kills failure #2)

**Rule: no component ever calls `fetch()` directly.** Everything goes through one `api()` wrapper that owns the
base URL, the bearer token, and the one error shape.

```ts
// api/client.ts — the ONLY place fetch() is called
const BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8080";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    readonly title: string,
    readonly detail: string,
  ) { super(`${status} ${title}: ${detail}`); }
}

export async function api<T>(
  path: string,
  opts: { method?: string; body?: unknown; token?: string; idempotencyKey?: string; signal?: AbortSignal } = {},
): Promise<T> {
  const headers: Record<string, string> = { "Accept": "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;
  if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;

  const res = await fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    // the ONE error shape — every route, every language
    throw new ApiError(res.status, data.type ?? "about:blank", data.title ?? "Error", data.detail ?? text);
  }
  return data as T;
}
```

Now every call is one line, and every error is an `ApiError` you can reason about: `await api("/items", {...})`.

## 2 · One error shape → one handler (kills failure #5's error case)

Because the envelope is identical everywhere, you map **status → UX** in exactly one place.

```ts
// api/handle.ts
export function toUserMessage(e: unknown): { message: string; action?: "login" | "retry" } {
  if (!(e instanceof ApiError)) return { message: "Something went wrong.", action: "retry" };
  switch (e.status) {
    case 401: return { message: "Please sign in again.", action: "login" };
    case 403: return { message: "You don't have access to that." };
    case 404: return { message: "Not found." };                 // also "not yours" — by design
    case 422: return { message: e.detail || "Please check your input." };
    case 429: return { message: "Too many requests — retrying…", action: "retry" };
    default:  return e.status >= 500
      ? { message: "The server had a problem — retrying…", action: "retry" }
      : { message: e.title };
  }
}
```

## 3 · Retries + backoff — and why they're SAFE here (kills failure #3)

The rule the backend lets you follow safely:
- **GET** (and other reads): retry freely — they're idempotent.
- **Writes** (POST/PATCH/DELETE): retry **only** when you send an `Idempotency-Key` — the backend dedups, so a
  retry can't create a second row or charge twice. Generate the key **once per user action** and reuse it across
  retries.
- **Never retry a 4xx** except `429`. A `422`/`404`/`401` won't get better by trying again.
- **Backoff:** exponential + jitter, a small cap, and honor `Retry-After` on `429` if present.

```ts
// api/retry.ts
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export async function withRetry<T>(fn: () => Promise<T>, tries = 4): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try { return await fn(); }
    catch (e) {
      const status = e instanceof ApiError ? e.status : 0;
      const retryable = status === 0 /* network */ || status === 429 || status >= 500;
      if (!retryable || attempt >= tries - 1) throw e;
      const backoff = Math.min(8000, 250 * 2 ** attempt) + Math.random() * 250; // jitter
      await sleep(backoff);
    }
  }
}

// a safe, retryable write: one key per action, reused across retries
export function createItem(fields: unknown, token: string) {
  const key = crypto.randomUUID();
  return withRetry(() => api("/items", { method: "POST", body: { fields }, token, idempotencyKey: key }));
}
```

## 4 · Never a blank screen (kills failures #1 and #5)

The blank screen is almost always: an unhandled rejection, a missing error/empty state, or a throw during
render. Two rules end it:

**(a) Every screen handles all three states — explicitly.** Loading, error, empty are not edge cases; they're
the design. A single `useApi` hook makes it a habit:

```ts
// api/useApi.ts (React; the same shape works in any framework)
export function useApi<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, set] = useState<{ status: "loading" | "error" | "ok"; data?: T; error?: unknown }>({ status: "loading" });
  useEffect(() => {
    let alive = true;
    set({ status: "loading" });
    fn().then(
      data  => alive && set({ status: "ok", data }),
      error => alive && set({ status: "error", error }),   // <-- caught, never an unhandled reject
    );
    return () => { alive = false; };
  }, deps);
  return state;
}

// usage — the component CAN'T blank: it renders one of four things
function Notes({ token }: { token: string }) {
  const s = useApi(() => api<{ results: Note[] }>("/items", { token }), [token]);
  if (s.status === "loading") return <Spinner />;
  if (s.status === "error")   return <ErrorNote {...toUserMessage(s.error)} />;
  if (!s.data!.results.length) return <Empty label="No notes yet" />;
  return <List items={s.data!.results} />;
}
```

**(b) An error boundary around each route** so a bug in ONE component degrades that component, not the whole app —
plus a global "backend unreachable" fallback:

```tsx
// one <ErrorBoundary> per route; a render throw shows a fallback, the rest of the app stays alive
<ErrorBoundary fallback={<RouteError />}>
  <Notes token={token} />
</ErrorBoundary>
```

> If you use TanStack Query / SWR, you get retries + the loading/error/empty states for free — configure them with
> the §2 handler and the §3 retry policy (retry reads; retry writes only with an Idempotency-Key). The rules are
> the same; the library just holds them.

## 5 · The front↔back contract — no drift (kills failure #4)

`.gutencode/contract.json` is the **source of truth**. Mirror the shapes you use (or generate them):

```ts
// api/types.ts — mirror contract.json; when the backend changes, regenerate and the compiler names the break
export type Problem = { type: string; title: string; status: number; detail: string };
export type Page<T> = { results: T[]; next_cursor: string | null };
export type Note   = { id: number; fields: Record<string, unknown>; /* … from contract.json … */ };
```

Discipline: when you pull a new backend edition, re-diff `contract.json` (or re-run your generator) **before**
touching UI code — a compile error is how you want to learn a field moved, not a blank screen in prod. The
shipped `verify.py` proves the backend matches its contract; this keeps *your* client matching it too.

## 6 · Authentication wiring (bearer + the 401 path)

- Log in → store the token (in memory + a refresh-safe place); attach it via the client's `token` option.
- On any `401`, clear the token and route to login (sessions carry an absolute expiry — they don't live forever).
- Centralize it: a `401` from `api()` can dispatch a single "signed out" event your app listens for once.

## 7 · Streaming UIs (SSE — for chat / assistant responses)

Routes that support streaming take `?stream=1` and emit Server-Sent Events: `event: delta` frames (append each
to the view) then a terminal `event: done` (the full result; finalize). The concatenated deltas equal the
non-streamed body — so you can build the streaming UI and trust it matches the sync response.

```ts
export async function stream(path: string, onDelta: (t: string) => void, token: string) {
  const res = await fetch(`${BASE}${path}?stream=1`, { headers: { Authorization: `Bearer ${token}` } });
  const reader = res.body!.getReader(); const dec = new TextDecoder();
  for (;;) {
    const { value, done } = await reader.read(); if (done) break;
    for (const frame of dec.decode(value).split("\n\n")) {
      if (frame.startsWith("event: delta")) onDelta(frame.split("data: ")[1] ?? "");
      // "event: done" → finalize
    }
  }
}
```

## 8 · Config in one place
- **Frontend:** the API base URL from an env var (`VITE_API_BASE` / `NEXT_PUBLIC_API_BASE`) — never hard-coded.
- **Backend:** set `CORS_ALLOWED_ORIGINS` to your site's origin (it's inert until set; it never reflects an
  unlisted origin). See `.env.example`.

## 9 · Pre-ship checklist (the wiring that prevents the blank screen)
```
[ ] every network call goes through the ONE api() client — zero raw fetch() in components
[ ] every screen renders loading / error / empty explicitly (not just the happy path)
[ ] every route is wrapped in an error boundary; there's a global "backend unreachable" fallback
[ ] reads retry with backoff; writes retry ONLY with an Idempotency-Key (one key per action)
[ ] a 401 clears the session and routes to login, from ONE place
[ ] a 429 backs off (honors Retry-After); 4xx (except 429) never retries
[ ] client types mirror .gutencode/contract.json; a backend change surfaces as a compile error
[ ] the API base URL comes from env; CORS_ALLOWED_ORIGINS is set on the backend
```

> The point: this backend gives you one error shape, one contract, and safe retries. Center your frontend on
> those three and the whole class of "blank screen because something wasn't wired" disappears.
