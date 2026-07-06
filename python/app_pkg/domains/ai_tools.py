"""ai_tools — the typed tool belt: a registry of tools any caller (an agent, a workflow) invokes over HTTP. Each
tool declares a TYPED CONTRACT — a description + an input_schema (JSON Schema: per-arg type + which are required) —
so a caller (or a model) knows the shape before it calls, and the args are VALIDATED against it. The dangerous
property is SAFE EXECUTION: an invoke whose args violate the contract (a missing required arg, OR an arg of the
wrong type) is CONTAINED (ok:false + the error, HTTP 200 — a tool failure is a RESULT, never a crash or a 5xx),
an unknown tool is an honest 404, and every tool is deterministic and BOUNDED (repeat is capped — output can never
explode). String ops work by CODEPOINTS, the ×3-identical semantic; text is normalized to well-formed Unicode (a
lone surrogate -> U+FFFD, matching the go json decoder) so a tool result is always serializable. Integer args are
STRICT and ×3-identical within the shared safe-integer range — 5.0 / "5" / true / null AND any magnitude beyond
±(2**53-1) are rejected uniformly via the runtime strict-int seam. The registry is static policy (no store); new
tools drop in behind the same typed invoke contract."""
from typing import Any, Callable, Dict, List, Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..core.errors import not_found, require_identity
from ..parts.well_formed import make_well_formed, require_well_formed

router = APIRouter(prefix="/tools", tags=["ai_tools"])

_REPEAT_CAP = 100   # the safety bound: repeat can never explode the output


def _repeat_n(args: Dict[str, Any]) -> int:
    n = args.get("n", 1)           # validated: present -> a strict int, absent -> the default (1)
    if n < 0:
        n = 0                      # a negative n yields empty, never an error
    return min(n, _REPEAT_CAP)     # BOUNDED: output can never explode


# an arg spec: (name, type, required, description). type is "string" | "integer" (the subset the live tools use).
ArgSpec = Tuple[str, str, bool, str]

# the ONE registry: name -> (description, [arg specs], fn). Static policy, identical ×3. The input_schema in the
# listing, the required[] and the per-arg validation are all DERIVED from the specs — one source per tool.
_TOOLS: Dict[str, Tuple[str, List[ArgSpec], Callable[[Dict[str, Any]], str]]] = {
    "upper": ("Uppercase the text by Unicode codepoint.",
              [("text", "string", True, "the text to uppercase")],
              lambda a: str(a["text"]).upper()),
    "reverse": ("Reverse the text by Unicode codepoint (non-BMP characters stay whole).",
                [("text", "string", True, "the text to reverse")],
                lambda a: "".join(reversed(str(a["text"])))),            # codepoint reverse
    "wordcount": ("Count the whitespace-separated words in the text.",
                  [("text", "string", True, "the text to count words in")],
                  lambda a: str(len(str(a["text"]).split()))),
    "repeat": ("Repeat the text n times; n is clamped to 0..100 so the output can never explode.",
               [("text", "string", True, "the text to repeat"),
                ("n", "integer", False, "how many times to repeat (clamped to 0..100; default 1)")],
               lambda a: str(a["text"]) * _repeat_n(a)),
}
_ORDER = ["repeat", "reverse", "upper", "wordcount"]   # the listing order: sorted, deterministic ×3


def _input_schema(specs: List[ArgSpec]) -> dict:
    # DERIVE the JSON-Schema input_schema from the specs (one source) — the MCP/OpenAI/Anthropic tool-contract shape.
    return {
        "type": "object",
        "properties": {name: {"type": typ, "description": desc} for (name, typ, _req, desc) in specs},
        "required": [name for (name, _typ, req, _desc) in specs if req],
    }


# 2**53-1 = Number.MAX_SAFE_INTEGER: the integer range every language represents EXACTLY. Beyond it the three
# runtimes diverge — python is arbitrary-precision, go's strconv.Atoi caps at int64, node loses precision in a float
# — so a magnitude past it is rejected uniformly ×3 rather than silently accepted.
_MAX_SAFE_INT = 9007199254740991


def _validate(args: Dict[str, Any], specs: List[ArgSpec]) -> str:
    # Validate args against the typed contract: every required arg present + every present arg the declared type.
    # Returns the error string, or "" when valid. Unknown (undeclared) args are IGNORED — lenient, matching the
    # field's tool schemas (a new optional arg never breaks an old caller). STRICT integer (reject 5.0 / "5" / true /
    # null / a magnitude past the safe range) is the python half of the runtime strict-int seam: json gives int for 5,
    # float for 5.0, bool for true, and bool subclasses int so it is excluded explicitly — identical ×3 with go
    # RequireIntRaw + node isStrictInt. An accepted string is normalized to well-formed Unicode (lone surrogate fix).
    for (name, typ, required, _desc) in specs:
        if name not in args:
            if required:
                return f"missing required arg '{name}'"
            continue
        v = args[name]
        if typ == "string":
            if not isinstance(v, str):
                return f"arg '{name}' must be a string"
            args[name] = make_well_formed(v)   # central: lone surrogate -> U+FFFD (well_formed part); keeps output ×3 + serializable
        if typ == "integer" and (not isinstance(v, int) or isinstance(v, bool) or abs(v) > _MAX_SAFE_INT):
            return f"arg '{name}' must be an integer"
    return ""


class InvokeIn(BaseModel):
    args: Dict[str, Any] = {}


@router.get("")
def list_tools() -> list:
    # read-scope: public — the global static tool catalog (each tool's name + typed contract), identical for every
    # caller, not per-owner. The contract is a function signature, deliberately public — it exposes no secret.
    return [{"name": name, "description": _TOOLS[name][0], "input_schema": _input_schema(_TOOLS[name][1])}
            for name in _ORDER]


@router.post("/{tool_name}/invoke")
def invoke(tool_name: str, data: InvokeIn, caller: str = Depends(require_identity)) -> dict:
    require_well_formed(tool_name, "tool name")   # central handler-side rule; label matches the go/node string ×3
    if tool_name not in _TOOLS:
        raise not_found("tool")
    _desc, specs, fn = _TOOLS[tool_name]
    err = _validate(data.args, specs)
    if err:
        # CONTAINED: a contract violation is a RESULT the caller can read — never a crash, never a 5xx
        return {"tool": tool_name, "ok": False, "output": "", "error": err}
    return {"tool": tool_name, "ok": True, "output": fn(data.args), "error": None}
