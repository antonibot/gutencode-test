#!/usr/bin/env python3
"""This backend as a Model Context Protocol (MCP) server -- every verified route becomes a callable tool.

    python mcp_server.py                                       speak MCP over stdio (what .mcp.json runs)
    python mcp_server.py --base-url http://127.0.0.1:9000      point tool calls at a backend on another port

The tool list is derived at launch from .gutencode/contract.json (the shipped machine map of this repo), so
the surface a client sees is exactly the route set the contract declares -- nothing more, nothing less. Tool
names follow the route mechanically: method + path segments joined by underscores, a {param} segment becoming
by_<param> (GET /things/{id} -> get_things_by_id). GET tools carry readOnlyHint; mutations destructiveHint.

Trust model -- zero new authority. This process stores no credential and mints nothing: each tools/call is
forwarded to the running backend over plain HTTP with the bearer YOU provide (the MCP_BEARER environment
variable, or an `authorization` argument on the call), so every wall the backend enforces -- identity, roles,
Idempotency-Key checks, request caps -- applies unchanged. A tool call can do nothing a curl with the same
token could not. Without a token, calls go unauthenticated and authenticated routes answer 401 as usual.

Environment:
    MCP_BASE_URL   where the backend answers; default http://127.0.0.1:8080 (the README quickstarts).
                   The shipped .mcp.json sets http://127.0.0.1:8080 to match `python dev.py`.
    MCP_BEARER     optional token sent as the Authorization header on every forwarded call.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "spine"
HTTP_TIMEOUT = 30


def _contract():
    path = os.path.join(HERE, ".gutencode", "contract.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"mcp_server.py: cannot read {path}: {e}\n")
        sys.exit(1)


def _slug(method, path):
    """Deterministic tool name for a route: method + path segments, {param} -> by_<param>, non [a-z0-9_] -> _."""
    parts = [method.lower()]
    for seg in path.strip("/").split("/"):
        if seg.startswith("{") and seg.endswith("}"):
            parts.append("by_" + seg[1:-1])
        elif seg:
            parts.append(seg)
    name = "_".join(parts).lower()
    return "".join(c if (c.isascii() and (c.isalnum() or c == "_")) else "_" for c in name)


def _first_clause(text, cap=160):
    """The leading clause of a module description, for a compact tool description."""
    s = " ".join((text or "").split())
    for sep in (" · ", ". ", "; "):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
            break
    return (s[:cap].rsplit(" ", 1)[0] if len(s) > cap else s).strip()


def _example_case(contract, method, path):
    """The first replayable contract case for a route: same method, path matched segment-by-segment with any
    {param} accepting one concrete segment. Prefers a clean 2xx case (no query string), else the first match."""
    want = path.strip("/").split("/")
    best = None
    for c in contract.get("tests") or []:
        if c.get("method") != method:
            continue
        got = str(c.get("path", "")).split("?")[0].strip("/").split("/")
        if len(got) != len(want):
            continue
        if not all(w == g or (w.startswith("{") and w.endswith("}")) for w, g in zip(want, got)):
            continue
        if 200 <= int(c.get("status", 0)) < 300 and "?" not in str(c.get("path", "")):
            return c
        best = best or c
    return best


def _json_type(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return None


def _input_schema(method, path, example):
    """Advisory input schema: path params + the example body's shape. The backend's own validation is the real
    authority -- a bad argument gets a contained 4xx from the backend, never a crash here."""
    props, required = {}, []
    for seg in path.strip("/").split("/"):
        if seg.startswith("{") and seg.endswith("}"):
            props[seg[1:-1]] = {"type": "string", "description": "path parameter"}
            required.append(seg[1:-1])
    if method != "GET":
        body = {"type": "object", "description": "JSON request body", "additionalProperties": True}
        ex = (example or {}).get("json")
        if isinstance(ex, dict) and ex:
            body["properties"] = {k: ({"type": t} if (t := _json_type(v)) else {}) for k, v in ex.items()}
        props["body"] = body
    props["query"] = {"type": "object", "description": "query string parameters", "additionalProperties": True}
    props["headers"] = {"type": "object", "description": "extra HTTP headers (e.g. Idempotency-Key where the "
                                                         "route demands one)", "additionalProperties": True}
    props["authorization"] = {"type": "string", "description": "bearer token (or full Authorization header "
                                                               "value) for this call; overrides MCP_BEARER"}
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def _annotations(method):
    if method == "GET":
        return {"readOnlyHint": True, "openWorldHint": False}
    a = {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False}
    if method in ("PUT", "DELETE"):
        a["idempotentHint"] = True
    return a


def build_tools(contract):
    """One tool per contract route (minus the contract's mcp.excluded set), in a stable order, names unique."""
    excluded = {(r.get("method"), r.get("path")) for r in (contract.get("mcp") or {}).get("excluded") or []}
    routes = []
    for dom, info in sorted((contract.get("domains") or {}).items()):
        for r in info.get("routes") or []:
            if (r["method"], r["path"]) not in excluded:
                routes.append((r["path"], r["method"], dom, info.get("desc") or ""))
    tools, taken = [], set()
    for path, method, dom, desc in sorted(routes):
        name = _slug(method, path)
        n = 2
        while name in taken:                       # two routes collapsing to one slug: deterministic suffix
            name = f"{_slug(method, path)}_{n}"
            n += 1
        taken.add(name)
        example = _example_case(contract, method, path)
        clause = _first_clause(desc)
        tools.append({
            "name": name,
            "description": f"{method} {path}" + (f" -- {dom}: {clause}" if clause else f" -- {dom}"),
            "inputSchema": _input_schema(method, path, example),
            "annotations": _annotations(method),
            "_meta": {"x-route": {"method": method, "path": path}},
        })
    return tools


def call_route(base_url, method, path, args):
    """Forward one tool call to the backend. Returns an MCP tool result; transport trouble is a contained tool
    error (isError), never a crash of the stdio loop."""
    url_path = path
    for seg in path.strip("/").split("/"):
        if seg.startswith("{") and seg.endswith("}"):
            key = seg[1:-1]
            if key not in args:
                return {"content": [{"type": "text", "text": f"missing required path parameter: {key}"}],
                        "isError": True}
            url_path = url_path.replace(seg, urllib.parse.quote(str(args[key]), safe=""))
    query = args.get("query") or {}
    if isinstance(query, dict) and query:
        url_path += "?" + urllib.parse.urlencode({str(k): str(v) for k, v in query.items()})
    headers = {str(k): str(v) for k, v in (args.get("headers") or {}).items()} \
        if isinstance(args.get("headers"), dict) else {}
    bearer = args.get("authorization") or headers.get("Authorization") or os.environ.get("MCP_BEARER") or ""
    if bearer:
        headers["Authorization"] = bearer if " " in bearer else f"Bearer {bearer}"
    data = None
    if method != "GET" and args.get("body") is not None:
        data = json.dumps(args["body"]).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url.rstrip("/") + url_path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            status, body = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:                    # a 4xx/5xx answer IS the backend speaking: relay it
        status, body = e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return {"content": [{"type": "text", "text": f"backend not reachable at {base_url} ({e}). Start it "
                                                     f"first (python dev.py) or set MCP_BASE_URL / --base-url "
                                                     f"to where it answers."}], "isError": True}
    return {"content": [{"type": "text", "text": f"HTTP {status}\n{body}"}], "isError": status >= 400}


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _reply(mid, result):
    _send({"jsonrpc": "2.0", "id": mid, "result": result})


def _reply_error(mid, code, message):
    _send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def serve(base_url):
    contract = _contract()
    tools = build_tools(contract)
    by_name = {t["name"]: t["_meta"]["x-route"] for t in tools}
    sys.stderr.write(f"mcp_server.py: {len(tools)} tools from .gutencode/contract.json; backend {base_url}\n")
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            _reply_error(None, -32700, "parse error: the request line is not valid JSON")
            continue
        mid, method = msg.get("id"), msg.get("method")
        if method is None or mid is None:          # a notification (initialized, cancelled, ...) or a response:
            continue                               # nothing to answer on a one-way message
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                proto = params.get("protocolVersion")
                if not isinstance(proto, str) or not proto:
                    _reply_error(mid, -32602, "initialize requires params.protocolVersion")
                    continue
                _reply(mid, {"protocolVersion": proto,       # the stable stdio core; we speak what you speak
                             "capabilities": {"tools": {}},
                             "serverInfo": {"name": APP_NAME,
                                            "version": str(contract.get("spine_version") or "0")}})
            elif method == "ping":
                _reply(mid, {})
            elif method == "tools/list":
                _reply(mid, {"tools": tools})
            elif method == "tools/call":
                name = params.get("name")
                route = by_name.get(name)
                if route is None:
                    _reply_error(mid, -32602, f"unknown tool: {name!r}")
                    continue
                args = params.get("arguments") or {}
                _reply(mid, call_route(base_url, route["method"], route["path"], args))
            else:
                _reply_error(mid, -32601, f"method not found: {method}")
        except Exception as e:                     # one bad message must never kill the session
            _reply_error(mid, -32603, f"internal error: {e}")
    return 0


def main(argv):
    base_url = os.environ.get("MCP_BASE_URL") or "http://127.0.0.1:8080"
    if "--base-url" in argv:
        i = argv.index("--base-url")
        if i + 1 >= len(argv):
            sys.exit("mcp_server.py: --base-url needs a value, e.g. --base-url http://127.0.0.1:9000")
        base_url = argv[i + 1]
    if sys.stdin is None or sys.stdout is None:
        sys.exit("mcp_server.py: needs a stdio channel (it is launched by an MCP client -- see .mcp.json)")
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    return serve(base_url)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
