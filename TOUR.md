# TOUR.md — your backend in 10 minutes

Two terminals. Terminal 1 runs the server; this file is terminal 2 — every step is copy-paste,
with a bash and a PowerShell form. Start the server:

    python dev.py        # serves whichever runtime this machine has on http://127.0.0.1:8080

(Using a per-language quickstart from README.md instead? Those examples sit on :8080 — either
set PORT=8080 first or swap the port in the URLs below.)

## 1 · Is it alive?
```bash
curl -s http://127.0.0.1:8080/health
# the contract expects: 200 {"status": "ok"}
```
```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

## 2 · Sign up + log in — a real account, a real token
Sign-up replies the same for a new and an existing account — deliberately, so nobody can probe
which accounts exist. The token comes from logging in.

```bash
curl -s -X POST http://127.0.0.1:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@ex.com", "password": "correct horse"}'
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@ex.com", "password": "correct horse"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s http://127.0.0.1:8080/auth/me -H "Authorization: Bearer $TOKEN"
```
```powershell
Invoke-RestMethod `
  -Method Post `
  http://127.0.0.1:8080/auth/register `
  -ContentType "application/json" `
  -Body '{"email": "alice@ex.com", "password": "correct horse"}'
$login = Invoke-RestMethod `
  -Method Post `
  http://127.0.0.1:8080/auth/login `
  -ContentType "application/json" `
  -Body '{"email": "alice@ex.com", "password": "correct horse"}'
$H = @{ Authorization = "Bearer $($login.access_token)" }
Invoke-RestMethod http://127.0.0.1:8080/auth/me -Headers $H
```

## 3 · The rest of the auth loop — verify · reset · invite (in dev)
Email-verification, password-reset, and invitations send a single-use token by "email" — the app
writes it to an outbox in the store instead of sending real mail. In development, read those tokens
with the shipped helper (run it with the SAME `DATABASE_PATH` / `DATABASE_URL` the server uses):

```bash
python scripts/read_outbox.py            # every pending verify / reset / invite token
```
Take the `token` from a row and POST it to the matching confirm route (see the route table in
README.md / requests.http) to finish the flow. There is NO route that leaks these tokens — this dev
helper is the documented way to close signup → verify → login → reset locally without a mail server.

## 4 · Create something, read it back
Everything you create is stamped with YOUR identity server-side — ownership comes from the
token, never from the request body. Replays are safe: re-send the same create and you get
the same object back or a clean conflict, never a silent duplicate.

```bash
curl -s -X POST http://127.0.0.1:8080/reporting/facts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"dataset": "deals", "key": "d2", "dimensions": {"stage": "won", "region": "us"}, "measures": {"value": 250, "count": 1}}'
# the contract expects: 201
curl -s "http://127.0.0.1:8080/reporting/facts" -H "Authorization: Bearer $TOKEN"
```
```powershell
Invoke-RestMethod `
  -Method Post `
  http://127.0.0.1:8080/reporting/facts `
  -Headers $H `
  -ContentType "application/json" `
  -Body '{"dataset": "deals", "key": "d2", "dimensions": {"stage": "won", "region": "us"}, "measures": {"value": 250, "count": 1}}'
Invoke-RestMethod http://127.0.0.1:8080/reporting/facts -Headers $H
```

## 5 · Call the AI surface
The AI answers offline and deterministically out of the box — no key, no network, no bill.
It is the same seam a real provider plugs into later (see INTEROP.md).

```bash
curl -s -X POST http://127.0.0.1:8080/agents/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "helper", "system_prompt": "be helpful"}'
# the contract expects: 201 {"id": 1, "name": "helper", "system_prompt": "be helpful"}
```
```powershell
Invoke-RestMethod `
  -Method Post `
  http://127.0.0.1:8080/agents/ `
  -Headers $H `
  -ContentType "application/json" `
  -Body '{"name": "helper", "system_prompt": "be helpful"}'
```

## 6 · Money — replays can't double-charge
Money-writing routes demand an `Idempotency-Key` header. Re-run either command below with the
SAME key and you get the same answer back — not a second charge. Retries are safe by design.

```bash
curl -s -X POST http://127.0.0.1:8080/invoices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: K1" \
  -H "Content-Type: application/json" \
  -d '{"customer": "acme", "currency": "usd", "tax": 100, "line_items": [{"description": "widget", "quantity": 3, "unit_amount": 500}, {"description": "setup fee", "quantity": 1, "unit_amount": 1000}]}'
# the contract expects: 201
```
```powershell
Invoke-RestMethod `
  -Method Post `
  http://127.0.0.1:8080/invoices `
  -Headers ($H + @{ "Idempotency-Key" = "K1" }) `
  -ContentType "application/json" `
  -Body '{"customer": "acme", "currency": "usd", "tax": 100, "line_items": [{"description": "widget", "quantity": 3, "unit_amount": 500}, {"description": "setup fee", "quantity": 1, "unit_amount": 1000}]}'
```

## 7 · Prove nothing broke
```bash
python verify.py
```
The same offline proof CI runs on every push: baseline intact, all three suites, invariants,
every route checked against the shipped contract. Run it after every change you make.

## 8 · Where next
- `requests.http` — all 169 routes, clickable (VS Code REST Client / JetBrains), the login
  token chained automatically
- `python scripts/seed.py` — what this tour did (and more) in one shot, through the public API
- http://127.0.0.1:8080/docs — interactive Swagger UI (python runtime only)
- `CUSTOMIZE.md` — add your first endpoint · `PRD_TEMPLATE.md` — spec a whole feature · agents start at `AGENT.md`
