"""Tool registry — register + dispatch. A missing tool, bad args, or a throwing tool all return
ToolResult(ok=False, error=…) — NEVER a crash; the observation is fed back to the loop."""
from typing import Any, Callable, Dict

from ..ports import ToolResult


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, Callable[[Dict[str, Any]], str]] = {}

    def register(self, name: str, fn: Callable[[Dict[str, Any]], str]) -> None:
        self._tools[name] = fn

    def run(self, name: str, args: Dict[str, Any]) -> ToolResult:
        if name not in self._tools:
            return ToolResult(ok=False, error=f"tool '{name}' not found")
        try:
            return ToolResult(ok=True, output=str(self._tools[name](args or {})))
        except Exception as exc:                       # a throwing tool is contained, never a crash
            return ToolResult(ok=False, error=f"{type(exc).__name__}: {exc}")
