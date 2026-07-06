"""ledger — a double-entry LEDGER, the correctness spine of fintech. Invariants (machine-checked by
invariant_test.py): every transaction balances (sum of signed amounts == 0) and has >= 2 entries; entries are
append-only/immutable (no update/delete route exists -> immutability by construction); balances are DERIVED from
the entries, never stored. Validation is STRICT (StrictInt: "100"/100.5/true -> 422) and runs BEFORE any write,
so a rejected transaction consumes no tx id and leaves no partial entries. State lives in the durable store seam.
ADMIN-ONLY: the ledger is financial infrastructure with no per-account owner model, so BOTH routes require
the 'admin' role (the core require_admin seam) — posting a transaction is a financial mutation, and a balance read
reveals financial position. No token is 401, a non-admin is 403, resolved BEFORE any body/path validation (×3)."""
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator

from ..core import store
from ..core.errors import IntPath, SafeInt, require_admin

router = APIRouter(prefix="/ledger", tags=["ledger"])
# state in `store`: seq "ledger_tx" the monotonic tx counter · ns "ledger_tx" key "<tid>" -> the WHOLE balanced
# transaction {id, entries} written as ONE atomic row (a crash can't leave a half-written, unbalanced tx). Same
# names + model in all three languages.


class EntryIn(BaseModel):
    account_id: SafeInt
    amount: SafeInt  # signed minor units: +debit / -credit


class TransactionIn(BaseModel):
    entries: List[EntryIn]

    @field_validator("entries")
    @classmethod
    def must_balance(cls, value: List[EntryIn]) -> List[EntryIn]:
        if len(value) < 2:
            raise ValueError("double-entry requires >= 2 entries")
        if sum(e.amount for e in value) != 0:
            raise ValueError("transaction does not balance: sum of entries must be 0 (debits == credits)")
        return value


class TransactionOut(BaseModel):
    id: int
    entries: List[EntryIn]


class BalanceOut(BaseModel):
    account_id: int
    balance: int


@router.post("/transactions", response_model=TransactionOut, status_code=201)
def post_transaction(data: TransactionIn, subject: str = Depends(require_admin)) -> TransactionOut:
    tid = store.next_id("ledger_tx")     # atomic, durable; a crash before the put below loses the id (a harmless gap)
    entries = [{"account_id": e.account_id, "amount": e.amount} for e in data.entries]
    store.put("ledger_tx", str(tid), {"id": tid, "entries": entries})   # the WHOLE balanced tx in ONE atomic write
    return TransactionOut(id=tid, entries=data.entries)


@router.get("/accounts/{account_id}/balance", response_model=BalanceOut)
def balance(account_id: IntPath, subject: str = Depends(require_admin)) -> BalanceOut:
    # unbounded-safe: scalar aggregate — sums the account's entries into a single balance, returns no collection; the O(n) scan is the documented store-swap-at-scale limit (a running-balance row is the Postgres upgrade).
    derived = sum(e["amount"] for tx in store.values("ledger_tx")
                  for e in tx["entries"] if e["account_id"] == account_id)
    return BalanceOut(account_id=account_id, balance=derived)   # DERIVED from the stored transactions, never stored
