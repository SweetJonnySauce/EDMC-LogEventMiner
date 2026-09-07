"""Pure syntax spans and line paths for formatted JSON in the CAPI viewer."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import json
import re
from typing import NamedTuple


JsonPath = tuple[str | int, ...]
_STRING = r'"(?:\\.|[^"\\])*"'
_TOKENS = re.compile(
    rf'(?P<key>{_STRING})(?=\s*:)|(?P<string>{_STRING})'
    r'|(?P<number>-?(?:\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|Infinity)|NaN)'
    r'|(?P<literal>true|false|null)|(?P<punctuation>[{}\[\],:])'
)


class SyntaxSpan(NamedTuple):
    kind: str
    start: int
    end: int


@dataclass(frozen=True)
class JsonPresentation:
    text: str
    spans: tuple[SyntaxSpan, ...]
    paths: tuple[JsonPath | None, ...]

    def trim_start(self, count: int) -> JsonPresentation:
        """Crop text and metadata together, retaining paths of surviving lines."""
        count = max(0, min(count, len(self.text)))
        if count == len(self.text):
            return JsonPresentation("", (), ())
        removed_lines = self.text.count("\n", 0, count)
        spans = tuple(
            SyntaxSpan(span.kind, max(span.start - count, 0), span.end - count)
            for span in self.spans if span.end > count
        )
        return JsonPresentation(self.text[count:], spans, self.paths[removed_lines:])

    def with_prefix(
        self, prefix: str, path: JsonPath | None = None, kind: str | None = None
    ) -> JsonPresentation:
        """Prepend complete header/notice lines without parsing them as JSON."""
        if not prefix.endswith("\n"):
            raise ValueError("Presentation prefixes must end with a newline")
        spans = [SyntaxSpan(kind, 0, len(prefix) - 1)] if kind else []
        spans.extend(SyntaxSpan(s.kind, s.start + len(prefix), s.end + len(prefix)) for s in self.spans)
        return JsonPresentation(
            prefix + self.text, tuple(spans), (path,) * prefix.count("\n") + self.paths
        )


@dataclass
class _Container:
    kind: str
    path: JsonPath
    key: str | None = None
    next_index: int = 0


def analyze_json(text: str, *, header_lines: int = 0) -> JsonPresentation:
    """Index serialized JSON, optionally skipping complete report header lines."""
    starts = [0] + [match.end() for match in re.finditer("\n", text) if match.end() < len(text)]
    paths: list[JsonPath | None] = [()] * len(text.splitlines())
    body_start = starts[header_lines] if header_lines < len(starts) else len(text)
    spans = [SyntaxSpan("header", 0, body_start - 1)] if body_start else []
    stack: list[_Container] = []

    def value_path() -> JsonPath:
        if not stack:
            return ()
        container = stack[-1]
        if container.kind == "[":
            path = container.path + (container.next_index,)
            container.next_index += 1
            return path
        path = container.path + (container.key,) if container.key is not None else container.path
        container.key = None
        return path

    for match in _TOKENS.finditer(text, body_start):
        kind = match.lastgroup
        token = match.group()
        spans.append(SyntaxSpan(kind, match.start(), match.end()))
        if kind == "key":
            key = json.loads(token)
            if stack:
                stack[-1].key = key
                path = stack[-1].path + (key,)
            else:
                path = (key,)
        elif token in ("{", "["):
            path = value_path()
            stack.append(_Container(token, path))
        elif token in ("}", "]"):
            path = stack.pop().path if stack else ()
        elif kind == "punctuation":
            continue
        else:
            path = value_path()
        paths[bisect_right(starts, match.start()) - 1] = path
    return JsonPresentation(text, tuple(spans), tuple(paths))


def format_json_path(path: JsonPath) -> str:
    """Format object names and array indexes on one breadcrumb line."""
    parts = ["$"]
    for part in path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        else:
            # Preserve Unicode but escape control characters, quotes and backslashes.
            parts.append(json.dumps(part, ensure_ascii=False)[1:-1])
    return " › ".join(parts)
