"""Built-in tools. `calc` walks the AST — NEVER eval() (no code injection); results format one-decimal so all
three languages produce identical observations (the cross-language contract pins 'answer: 4.0')."""
import ast
import operator
from typing import Any, Callable, Dict

from .registry import ToolRegistry

_OPS: Dict[type, Callable] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.USub: operator.neg, ast.Mod: operator.mod,
}


def _eval(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


def calc(args: Dict[str, Any]) -> str:
    # the except tuple MUST cover every arithmetic failure so the SAME bad expr is "error: invalid expression"
    # in all three langs (the cross-language observation contract): ZeroDivisionError (1/0, 1%0 — Go panics on
    # int64%0, Node yields Infinity/NaN), OverflowError (a ~309-digit int literal float()-overflows — Go/Node
    # reject it at parse via ParseFloat-ErrRange / !isFinite, so Python MUST too, else the observations diverge).
    try:
        v = _eval(ast.parse(str(args.get('expr', '')), mode='eval').body)
        if v != v or v in (float("inf"), float("-inf")):  # NaN / ±Inf -> invalid (matches Go/Node non-finite reject)
            return "error: invalid expression"
        return f"{v:.1f}"
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError):
        return "error: invalid expression"


def echo(args: Dict[str, Any]) -> str:
    return str(args.get("text", ""))


def register_builtins(registry: ToolRegistry) -> None:
    registry.register("calc", calc)
    registry.register("echo", echo)
