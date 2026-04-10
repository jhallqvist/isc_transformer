"""
isc.named.visitor
~~~~~~~~~~~~~~~~~
ValidatingVisitor: walks the raw AST produced by the parser, validates it
against a schema expressed in the DSL, and produces a typed dataclass tree.

Public API
----------
    from isc.named.visitor import ValidatingVisitor, ValidationError, Severity
    from isc.named.schema  import NAMED_CONF
    from isc.named.parser  import parse

    conf   = parse(text)
    v      = ValidatingVisitor(NAMED_CONF, strict=False)
    result = v.visit(conf)

    for err in v.errors:
        print(err)

Design
------
The visitor is a peel-and-dispatch loop. Each method receives an AST node
and a DSL spec, peels one wrapper layer from the spec, and delegates to the
appropriate sub-method. The visitor never raises — all problems are collected
in self.errors and the caller always receives a (possibly partial) typed tree.

Token flow
----------
Tokens are passed as an immutable sequence. Each resolution method returns
(value, remaining_tokens) so the cursor advances naturally without mutation.

Reference resolution
--------------------
The visitor registers all reference types (AclReference, KeyReference, etc.)
during the walk and resolves them in a single reconciliation step before
returning the root dataclass. This allows forward references — a reference
may appear before its definition in the file.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from isc.named.lexer  import Token, Word, Number, String
from isc.named.parser import Conf, Statement, Block, Negated, Node

from isc.named.dsl import (
    # types
    IpAddressType, IpPrefixType, BooleanType, Integer, FixedPoint,
    Percentage, Size, StringType, EnumType, Duration, RrTypeList,
    TsigAlgorithm, Base64, Unlimited,
    # reference types
    AclReference, KeyReference, TlsReference, ViewReference,
    # directives
    Arg, Keyword, Optional, Negatable, Wildcard, Deprecated,
    Multiple, OneOf, ExclusiveOf, Variadic, ListOf, Context,
    # statement
    StatementDef,
)


_BUILTIN_ACLS = frozenset({
    "any", "none", "localhost", "localnets",
})

__all__ = [    "ValidatingVisitor",
    "ValidationError",
    "Severity",
    "UnresolvedReference",
]


# ---------------------------------------------------------------------------
# Error reporting
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    ERROR   = "ERROR"
    WARNING = "WARNING"
    INFO    = "INFO"


@dataclass
class ValidationError:
    message:  str
    severity: Severity = Severity.ERROR
    line:     int | None = None
    col:      int | None = None
    context:  str = ""

    def __str__(self) -> str:
        loc = f"line {self.line}, col {self.col}" if self.line else "unknown location"
        ctx = f" [{self.context}]" if self.context else ""
        return f"{self.severity}{ctx} at {loc}: {self.message}"


# ---------------------------------------------------------------------------
# Unresolved reference — registered during walk, resolved after
# ---------------------------------------------------------------------------

@dataclass
class UnresolvedReference:
    name: str
    kind: str        # "acl", "key", "tls", "view"
    raw:  Any        # original AST node for error reporting


# ---------------------------------------------------------------------------
# Duration parsing helpers
# ---------------------------------------------------------------------------

_TTL_RE = re.compile(
    r'^(?:(\d+)[wW])?(?:(\d+)[dD])?(?:(\d+)[hH])?(?:(\d+)[mM])?(?:(\d+)[sS]?)?$'
)
_TTL_FACTORS = (604800, 86400, 3600, 60, 1)

_ISO_RE = re.compile(
    r'^[Pp]'
    r'(?:(\d+)[Yy])?'
    r'(?:(\d+)[Mm])?'
    r'(?:(\d+)[Ww])?'
    r'(?:(\d+)[Dd])?'
    r'(?:[Tt]'
    r'(?:(\d+)[Hh])?'
    r'(?:(\d+)[Mm])?'
    r'(?:(\d+)[Ss])?'
    r')?$'
)
_ISO_FACTORS = (
    365 * 86400,   # years  (approximate)
    30  * 86400,   # months (approximate)
    7   * 86400,   # weeks
    86400,         # days
    3600,          # hours
    60,            # minutes
    1,             # seconds
)

_TSIG_BASE = frozenset({
    "hmac-md5", "hmac-sha1",   "hmac-sha224",
    "hmac-sha256", "hmac-sha384", "hmac-sha512",
    "gss-tsig",
})
_TSIG_NO_TRUNC = frozenset({"hmac-md5", "gss-tsig"})


def _parse_ttl(s: str) -> int | None:
    m = _TTL_RE.fullmatch(s.strip())
    if not m or not any(m.groups()):
        return None
    return sum(
        int(g) * f for g, f in zip(m.groups(), _TTL_FACTORS) if g
    )


def _parse_iso8601(s: str) -> int | None:
    if s.upper() == "P":
        return 0
    m = _ISO_RE.fullmatch(s.strip())
    if not m:
        return None
    return sum(
        int(g) * f for g, f in zip(m.groups(), _ISO_FACTORS) if g
    )


# ---------------------------------------------------------------------------
# Visitor
# ---------------------------------------------------------------------------

class ValidatingVisitor:
    """
    Validates a raw named.conf AST against a DSL schema and produces
    a typed dataclass tree.

    Parameters
    ----------
    schema : Context
        The top-level schema. Typically NAMED_CONF from isc.named.schema.
    strict : bool
        If True unknown keywords are errors. If False (default) they
        produce a WARNING and the statement is skipped.
    """

    def __init__(self, schema: Context, strict: bool = False) -> None:
        self._schema  = schema
        self._strict  = strict
        self.errors:  list[ValidationError]     = []
        self._refs:   list[UnresolvedReference] = []
        self._defs:   dict[str, dict[str, Any]] = {
            "acl": {}, "key": {}, "tls": {}, "view": {},
        }

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def visit(self, conf: Conf) -> Any:
        """Validate the root Conf node and return the typed root dataclass."""
        result = self._visit_context(conf, self._schema)
        self._resolve_references()
        return result

    # ------------------------------------------------------------------
    # Error helpers
    # ------------------------------------------------------------------

    def _err(
        self,
        message:  str,
        node:     Any   = None,
        severity: Severity = Severity.ERROR,
        context:  str   = "",
    ) -> None:
        line = col = None
        span = getattr(node, "span", None)
        if span:
            line, col = span.line, span.col
        self.errors.append(ValidationError(
            message=message, severity=severity,
            line=line, col=col, context=context,
        ))

    def _ctx(self, *parts: str) -> str:
        return "/".join(p for p in parts if p)

    # ------------------------------------------------------------------
    # Context — resolves to a dataclass
    # ------------------------------------------------------------------

    def _visit_context(self, node: Conf | Block, schema: Context) -> Any:
        """
        Walk the body of a Conf or Block node, matching each child
        statement against the schema and assembling a kwargs dict.
        """
        # Separate StatementDef entries from Keyword/Arg entries
        stmt_unique:   dict[str, StatementDef]               = {}
        stmt_multiple: dict[str, StatementDef]               = {}
        kw_entries:    dict[str, Any]                        = {}  # sentinel → spec
        exclusive_groups: list[tuple[int, dict[str, StatementDef]]] = []

        for i, entry in enumerate(schema.statements):
            unwrapped = entry.inner if isinstance(entry, (Multiple, Deprecated)) else entry

            if isinstance(entry, Multiple) and isinstance(unwrapped, StatementDef):
                stmt_multiple[unwrapped.keyword] = unwrapped
            elif isinstance(entry, ExclusiveOf):
                group: dict[str, StatementDef] = {}
                for opt in entry.options:
                    group[opt.keyword] = opt
                exclusive_groups.append((i, group))
            elif isinstance(unwrapped, StatementDef):
                stmt_unique[unwrapped.keyword] = unwrapped
            elif isinstance(entry, (Keyword, Optional)):
                # Keyword/Optional(Keyword) at context level
                inner = entry.inner if isinstance(entry, Optional) else entry
                if isinstance(inner, Keyword):
                    sentinel = self._arg_name(inner)
                    kw_entries[sentinel] = entry
                elif isinstance(inner, Arg):
                    sentinel = inner.name
                    kw_entries[sentinel] = entry
            elif isinstance(entry, Arg):
                kw_entries[entry.name] = entry

        kwargs:         dict[str, Any] = {}
        seen_unique:    set[str]       = set()
        seen_exclusive: dict[int, str] = {}

        for child in node.body:
            negated = isinstance(child, Negated)
            inner   = child.inner if negated else child

            if not isinstance(inner, Statement):
                self._err(
                    f"Expected a statement, got {type(inner).__name__}",
                    child,
                )
                continue

            keyword = self._peek_keyword(inner)
            if not keyword:
                self._err("Statement has no keyword", inner)
                continue

            # Deprecated warning
            for entry in schema.statements:
                if (isinstance(entry, Deprecated)
                        and isinstance(entry.inner, StatementDef)
                        and entry.inner.keyword == keyword):
                    self._err(
                        f"'{keyword}' is deprecated",
                        inner, severity=Severity.WARNING,
                    )
                    break

            # Match against Keyword entries first (context-level keyword/value)
            if keyword in kw_entries:
                spec  = kw_entries[keyword]
                tokens = list(inner.values)[1:]  # drop the keyword token itself
                attr  = keyword.replace("-", "_")
                if isinstance(spec, (Keyword, Optional)):
                    inner_spec = spec.inner if isinstance(spec, Optional) else spec
                    inner_arg  = inner_spec.inner if isinstance(inner_spec, Keyword) else inner_spec
                    if tokens:
                        result, _ = self._resolve_arg(inner_arg, tokens, inner)
                    else:
                        result = None
                elif isinstance(spec, Arg):
                    result, _ = self._resolve_arg(spec, tokens, inner) if tokens else (None, [])
                else:
                    result = None
                kwargs[attr] = result
                continue

            # Match against StatementDef entries
            sdef     = None
            group_id = None

            if keyword in stmt_unique:
                sdef = stmt_unique[keyword]
                if keyword in seen_unique:
                    self._err(f"'{keyword}' may only appear once", inner)
                    continue
                seen_unique.add(keyword)
            elif keyword in stmt_multiple:
                sdef = stmt_multiple[keyword]
            else:
                for gid, group in exclusive_groups:
                    if keyword in group:
                        sdef     = group[keyword]
                        group_id = gid
                        break

            if sdef is None:
                sev = Severity.ERROR if self._strict else Severity.WARNING
                self._err(f"Unknown keyword '{keyword}'", inner, severity=sev)
                continue

            if group_id is not None:
                if group_id in seen_exclusive:
                    self._err(
                        f"Only one exclusive option allowed, "
                        f"already saw '{seen_exclusive[group_id]}', got '{keyword}'",
                        inner,
                    )
                    continue
                seen_exclusive[group_id] = keyword

            # Register definitions
            if keyword in self._defs:
                value = self._visit_statement(inner, sdef)
                self._defs[keyword][self._first_arg_value(value)] = value
            else:
                value = self._visit_statement(inner, sdef)

            attr = keyword.replace("-", "_")
            if keyword in stmt_multiple:
                existing = kwargs.get(attr, [])
                if isinstance(value, list):
                    kwargs[attr] = existing + value
                else:
                    existing.append(value)
                    kwargs[attr] = existing
            else:
                kwargs[attr] = value

        return kwargs

    # ------------------------------------------------------------------
    # Statement — resolves params and instantiates node_class
    # ------------------------------------------------------------------

    def _visit_statement(self, node: Statement, sdef: StatementDef) -> Any:
        """Resolve a statement's params and return the typed node."""
        # values[0] is the keyword token — skip it
        tokens = list(node.values)[1:]
        kwargs = {}

        for spec in sdef.params:
            result, tokens = self._resolve_param(spec, tokens, node)
            if isinstance(result, dict):
                kwargs.update(result)
            elif result is not None:
                name = self._arg_name(spec)
                if name:
                    kwargs[name.replace("-", "_")] = result

        if tokens:
            self._err(
                f"Unexpected tokens in '{sdef.keyword}': "
                + ", ".join(repr(getattr(t, "raw", t)) for t in tokens),
                node,
            )

        if sdef.node_class is None:
            # Flatten — return raw list or dict for the parent to absorb
            return list(kwargs.values())[0] if len(kwargs) == 1 else kwargs

        return sdef.node_class(**kwargs)

    # ------------------------------------------------------------------
    # Param resolution — peel one wrapper layer then delegate
    # ------------------------------------------------------------------

    def _resolve_param(
        self,
        spec:   Any,
        tokens: list,
        node:   Any = None,
    ) -> tuple[Any, list]:
        """
        Peel the outermost DSL wrapper and delegate.
        Returns (resolved_value, remaining_tokens).
        """
        if isinstance(spec, Optional):
            return self._resolve_optional(spec, tokens, node)

        if isinstance(spec, Keyword):
            return self._resolve_keyword(spec, tokens, node)

        if isinstance(spec, Negatable):
            return self._resolve_negatable(spec, tokens, node)

        if isinstance(spec, Wildcard):
            return self._resolve_wildcard(spec, tokens, node)

        if isinstance(spec, Variadic):
            return self._resolve_variadic(spec, tokens, node)

        if isinstance(spec, Arg):
            return self._resolve_arg(spec, tokens, node)

        if isinstance(spec, ListOf):
            # ListOf as a bare param — the block must be in tokens
            block = self._extract_block(tokens)
            if block is None:
                self._err("Expected a block '{ }'", node)
                return [], tokens
            tokens = [t for t in tokens if t is not block]
            return self._resolve_list_of(block, spec, node), tokens

        if isinstance(spec, Context):
            block = self._extract_block(tokens)
            if block is None:
                self._err("Expected a block '{ }'", node)
                return {}, tokens
            tokens = [t for t in tokens if t is not block]
            kwargs = self._visit_context(block, spec)
            return kwargs, tokens

        self._err(f"Unhandled spec type {type(spec).__name__}", node)
        return None, tokens

    def _resolve_optional(
        self, spec: Optional, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """Absence is fine — return None without error."""
        result, remaining = self._resolve_param(spec.inner, tokens, node)
        if result is None:
            name = self._arg_name(spec)
            return None, tokens   # restore original tokens on absence
        return result, remaining

    def _resolve_keyword(
        self, spec: Keyword, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """
        Scan for the sentinel word anywhere in the remaining tokens.
        Consume it and resolve what follows.
        """
        inner    = spec.inner
        sentinel = self._arg_name(inner)

        # Find sentinel in positional tokens
        sentinel_idx = next(
            (i for i, t in enumerate(tokens)
             if isinstance(t, Word) and t.value == sentinel),
            None,
        )
        if sentinel_idx is None:
            return None, tokens   # absent — caller (Optional) handles it

        tokens = list(tokens)
        tokens.pop(sentinel_idx)   # consume sentinel

        # What follows the sentinel?
        inner_spec = inner if isinstance(inner, Arg) else inner.inner
        result, tokens = self._resolve_param(inner_spec, tokens, node)
        return result, tokens

    def _resolve_negatable(
        self, spec: Negatable, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """Pass through — negation is on the AST node, not the token stream."""
        return self._resolve_param(spec.inner, tokens, node)

    def _resolve_wildcard(
        self, spec: Wildcard, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """If next token is '*' resolve to None, otherwise use inner type."""
        if tokens and isinstance(tokens[0], Word) and tokens[0].value == "*":
            return None, tokens[1:]
        return self._resolve_param(spec.inner, tokens, node)

    def _resolve_variadic(
        self, spec: Variadic, tokens: list, node: Any
    ) -> tuple[list, list]:
        """Consume all remaining tokens of the inner type."""
        results = []
        while tokens and not isinstance(tokens[0], Block):
            coerced, err = self._coerce(tokens[0], spec.inner)
            if err:
                break
            results.append(coerced)
            tokens = tokens[1:]
        return results, tokens

    def _resolve_arg(
        self, spec: Arg, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """
        Try each type in spec.types in order.
        Returns the first successful coercion.
        """
        if not tokens:
            self._err(f"Missing value for '{spec.name}'", node)
            return None, tokens

        tok = tokens[0]

        for type_spec in spec.types:
            if isinstance(type_spec, ListOf):
                if isinstance(tok, Block):
                    result = self._resolve_list_of(tok, type_spec, node)
                    return result, tokens[1:]
                continue

            if isinstance(type_spec, Context):
                if isinstance(tok, Block):
                    result = self._visit_context(tok, type_spec)
                    return result, tokens[1:]
                continue

            coerced, err = self._coerce(tok, type_spec)
            if err is None:
                return coerced, tokens[1:]

        self._err(
            f"'{spec.name}': expected "
            + " or ".join(type(t).__name__ for t in spec.types)
            + f", got {getattr(tok, 'raw', repr(tok))!r}",
            tok,
        )
        return None, tokens[1:]

    # ------------------------------------------------------------------
    # ListOf — resolves a Block body into a homogeneous list
    # ------------------------------------------------------------------

    def _resolve_list_of(
        self, block: Block, spec: ListOf, node: Any
    ) -> list:
        results = []
        for child in block.body:
            negated = isinstance(child, Negated)
            inner   = child.inner if negated else child

            result = self._resolve_list_element(inner, spec, node)

            if result is None:
                continue

            if spec.node_class is not None and isinstance(result, dict):
                result = spec.node_class(**result)

            # Attach negation if the element supports it
            if negated and hasattr(result, "negated"):
                result.negated = True

            results.append(result)

        return results

    def _resolve_list_element(
        self, node: Any, spec: ListOf, parent: Any
    ) -> Any:
        """Resolve one element inside a ListOf block."""
        inner = spec.inner

        if isinstance(inner, Negatable):
            inner = inner.inner

        if isinstance(inner, StatementDef):
            if not isinstance(node, Statement):
                self._err(
                    f"Expected a statement, got {type(node).__name__}",
                    node,
                )
                return None
            keyword = self._peek_keyword(node)
            if keyword != inner.keyword:
                self._err(
                    f"Expected '{inner.keyword}', got '{keyword}'",
                    node,
                )
                return None
            return self._visit_statement(node, inner)

        if isinstance(inner, OneOf):
            return self._resolve_one_of_element(node, inner, parent)

        if isinstance(inner, Arg):
            # Single token element
            if isinstance(node, Statement) and len(node.values) == 1:
                tok = node.values[0]
                result, tokens = self._resolve_arg(inner, [tok], node)
                return result
            self._err(
                f"Expected a single value for '{inner.name}'", node,
            )
            return None

        # Bare type spec (e.g. KeyReference() directly in ListOf)
        if isinstance(node, Statement):
            values = list(node.values)
            if len(values) == 1:
                coerced, err = self._coerce(values[0], inner)
                if err:
                    self._err(err, values[0])
                    return None
                return coerced
            # Multi-token statement (e.g. key "name")
            coerced, err = self._coerce(node, inner)
            if err:
                self._err(err, node)
                return None
            return coerced

        return None

    def _resolve_one_of_element(
        self, node: Any, spec: OneOf, parent: Any
    ) -> Any:
        """Try each OneOf option against the current node."""
        for option in spec.options:
            if isinstance(option, StatementDef):
                if not isinstance(node, Statement):
                    continue
                keyword = self._peek_keyword(node)
                if keyword == option.keyword:
                    return self._visit_statement(node, option)
                continue

            # Value-level option
            if isinstance(node, Statement) and len(node.values) == 1:
                coerced, err = self._coerce(node.values[0], option)
                if err is None:
                    return coerced
            elif isinstance(node, (Word, String, Number)):
                coerced, err = self._coerce(node, option)
                if err is None:
                    return coerced

        self._err(
            f"No matching option in OneOf for {getattr(node, 'raw', repr(node))!r}",
            node,
        )
        return None

    # ------------------------------------------------------------------
    # Coercion — token → Python value
    # ------------------------------------------------------------------

    def _coerce(self, node: Any, type_spec: Any) -> tuple[Any, str | None]:
        """
        Attempt to coerce a raw AST node to the Python type described by
        type_spec. Returns (coerced_value, error_message | None).
        """
        if isinstance(type_spec, IpAddressType):
            return self._coerce_ip_address(node)

        if isinstance(type_spec, IpPrefixType):
            return self._coerce_ip_prefix(node)

        if isinstance(type_spec, BooleanType):
            return self._coerce_boolean(node)

        if isinstance(type_spec, Integer):
            return self._coerce_integer(node, type_spec)

        if isinstance(type_spec, FixedPoint):
            return self._coerce_fixed_point(node, type_spec)

        if isinstance(type_spec, Percentage):
            return self._coerce_percentage(node, type_spec)

        if isinstance(type_spec, Size):
            return self._coerce_size(node, type_spec)

        if isinstance(type_spec, Duration):
            return self._coerce_duration(node)

        if isinstance(type_spec, StringType):
            return self._coerce_string(node)

        if isinstance(type_spec, EnumType):
            return self._coerce_enum(node, type_spec)

        if isinstance(type_spec, RrTypeList):
            return self._coerce_rr_type_list(node)

        if isinstance(type_spec, TsigAlgorithm):
            return self._coerce_tsig_algorithm(node)

        if isinstance(type_spec, Base64):
            return self._coerce_base64(node)

        if isinstance(type_spec, Unlimited):
            return self._coerce_unlimited(node)

        if isinstance(type_spec, AclReference):
            return self._coerce_reference(node, "acl")

        if isinstance(type_spec, KeyReference):
            return self._coerce_reference(node, "key")

        if isinstance(type_spec, TlsReference):
            return self._coerce_reference(node, "tls")

        if isinstance(type_spec, ViewReference):
            return self._coerce_reference(node, "view")

        return None, f"unhandled type spec {type(type_spec).__name__}"

    # ------------------------------------------------------------------
    # Individual coercion methods
    # ------------------------------------------------------------------

    def _coerce_ip_address(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected an IP address, got {type(node).__name__}"
        if node.value == "*":
            return node.value, None   # wildcard — valid in inet/listen-on
        try:
            return ipaddress.ip_address(node.value), None
        except ValueError:
            return None, f"{node.value!r} is not a valid IP address"

    def _coerce_ip_prefix(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected an IP prefix, got {type(node).__name__}"
        if "/" not in node.value:
            return None, f"{node.value!r} is not a valid IP prefix"
        try:
            return ipaddress.ip_network(node.value, strict=False), None
        except ValueError:
            return None, f"{node.value!r} is not a valid IP prefix"

    def _coerce_boolean(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, Number)):
            return None, f"expected a boolean, got {type(node).__name__}"
        v = node.value if isinstance(node, (Word, Number)) else node.raw
        if str(v).lower() in ("yes", "true", "1"):
            return True, None
        if str(v).lower() in ("no", "false", "0"):
            return False, None
        return None, f"{node.raw!r} is not a valid boolean (yes/no, true/false, 1/0)"

    def _coerce_integer(
        self, node: Any, spec: Integer
    ) -> tuple[Any, str | None]:
        if not isinstance(node, Number):
            return None, f"expected an integer, got {type(node).__name__}"
        v = node.value
        if spec.min is not None and v < spec.min:
            return None, f"{v} is below minimum {spec.min}"
        if spec.max is not None and v > spec.max:
            return None, f"{v} exceeds maximum {spec.max}"
        return v, None

    def _coerce_fixed_point(
        self, node: Any, spec: FixedPoint
    ) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected a fixed point value, got {type(node).__name__}"
        m = re.fullmatch(r'(\d{1,5})\.(\d{2})', node.value)
        if not m:
            return None, f"{node.value!r} is not a valid fixed point value"
        v = float(node.value)
        if spec.min is not None and v < spec.min:
            return None, f"{v} is below minimum {spec.min}"
        if spec.max is not None and v > spec.max:
            return None, f"{v} exceeds maximum {spec.max}"
        return v, None

    def _coerce_percentage(
        self, node: Any, spec: Percentage
    ) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected a percentage, got {type(node).__name__}"
        m = re.fullmatch(r'(\d+)%', node.value)
        if not m:
            return None, f"{node.value!r} is not a valid percentage"
        v = int(m.group(1))
        if spec.min is not None and v < spec.min:
            return None, f"{v}% is below minimum {spec.min}%"
        if spec.max is not None and v > spec.max:
            return None, f"{v}% exceeds maximum {spec.max}%"
        return v, None

    def _coerce_size(
        self, node: Any, spec: Size
    ) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String, Number)):
            return None, f"expected a size value, got {type(node).__name__}"
        m = re.fullmatch(r'(\d+)([kmgKMG])?', node.raw)
        if not m:
            return None, f"{node.raw!r} is not a valid size"
        v      = int(m.group(1))
        suffix = (m.group(2) or "").lower()
        v     *= {"k": 1024, "m": 1024**2, "g": 1024**3}.get(suffix, 1)
        if spec.min is not None and v < spec.min:
            return None, f"{v} is below minimum {spec.min}"
        if spec.max is not None and v > spec.max:
            return None, f"{v} exceeds maximum {spec.max}"
        return v, None

    def _coerce_duration(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String, Number)):
            return None, f"expected a duration, got {type(node).__name__}"
        if isinstance(node, Number):
            return node.value, None
        s = node.value
        if s.upper().startswith("P"):
            v = _parse_iso8601(s)
            if v is not None:
                return v, None
        v = _parse_ttl(s)
        if v is not None:
            return v, None
        return None, f"{node.value!r} is not a valid duration"

    def _coerce_string(self, node: Any) -> tuple[Any, str | None]:
        if isinstance(node, String):
            return node.value, None
        if isinstance(node, Word):
            return node.value, None
        return None, f"expected a string, got {type(node).__name__}"

    def _coerce_enum(
        self, node: Any, spec: EnumType
    ) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected one of {spec.values}"
        if node.value not in spec.values:
            return None, f"{node.value!r} is not one of {spec.values}"
        return node.value, None

    def _coerce_rr_type_list(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected an RR type list, got {type(node).__name__}"
        if node.value.upper() == "ANY":
            return ["ANY"], None
        return [node.value.upper()], None

    def _coerce_tsig_algorithm(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected an algorithm name, got {type(node).__name__}"
        value  = node.value.lower()
        parts  = value.rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            base, trunc = parts[0], int(parts[1])
            if base not in _TSIG_BASE:
                return None, f"{node.value!r} is not a valid TSIG algorithm"
            if base in _TSIG_NO_TRUNC:
                return None, f"{base} does not support truncation"
            return (base, trunc), None
        if value not in _TSIG_BASE:
            return None, f"{node.value!r} is not a valid TSIG algorithm"
        return (value, None), None

    def _coerce_base64(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, String):
            return None, f"expected a quoted Base64 string, got {type(node).__name__}"
        stripped = node.value.replace(" ", "").replace("\n", "")
        try:
            base64.b64decode(stripped, validate=True)
            return stripped, None
        except Exception:
            return None, f"{node.value!r} is not valid Base64"

    def _coerce_unlimited(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, Word):
            return None, f"expected 'unlimited', got {type(node).__name__}"
        if node.value != "unlimited":
            return None, f"expected 'unlimited', got {node.value!r}"
        return None, None   # None signals no limit

    def _coerce_reference(
        self, node: Any, kind: str
    ) -> tuple[Any, str | None]:
        """
        Coerce a reference to a named definition.
        Accepts two forms:
          - Bare token (Word/String):       "myacl", "mykey"
          - Statement with sentinel:        key "mykey"
        """
        if isinstance(node, (Word, String)):
            name = node.value
        elif isinstance(node, Statement):
            values = list(node.values)
            if (len(values) == 2
                    and isinstance(values[0], Word)
                    and values[0].value == kind
                    and isinstance(values[1], (Word, String))):
                name = values[1].value
            elif (len(values) == 1
                    and isinstance(values[0], (Word, String))):
                name = values[0].value
            else:
                return None, (
                    f"expected a {kind} reference, got {node!r}"
                )
        else:
            return None, (
                f"expected a {kind} reference, got {type(node).__name__}"
            )

        self._refs.append(
            UnresolvedReference(name=name, kind=kind, raw=node)
        )
        return name, None

    # ------------------------------------------------------------------
    # Reference resolution — runs after full tree is walked
    # ------------------------------------------------------------------

    def _resolve_references(self) -> None:
        for ref in self._refs:
            if ref.kind == "acl" and ref.name in _BUILTIN_ACLS:
                continue
            if ref.name not in self._defs.get(ref.kind, {}):
                self._err(
                    f"{ref.kind} '{ref.name}' is referenced but never defined",
                    ref.raw,
                    severity=Severity.ERROR,
                )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _peek_keyword(self, node: Statement) -> str:
        """Return the first Word or String value from a statement."""
        for v in node.values:
            if isinstance(v, (Word, String)):
                return v.value
        return ""

    def _arg_name(self, spec: Any) -> str:
        """Unwrap combinators until the inner Arg name is reached."""
        if isinstance(spec, Arg):
            return spec.name
        if isinstance(spec, (Optional, Keyword, Negatable,
                              Wildcard, Deprecated, Multiple)):
            return self._arg_name(spec.inner)
        if isinstance(spec, StatementDef):
            return spec.keyword
        return ""

    def _extract_block(self, tokens: list) -> Block | None:
        """Find and return the first Block in the token list."""
        for t in tokens:
            if isinstance(t, Block):
                return t
        return None

    def _first_arg_value(self, value: Any) -> str:
        """Extract the name/identifier from a typed node for registration."""
        if hasattr(value, "name"):
            return value.name
        return str(value)
