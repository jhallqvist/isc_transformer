"""
isc.named.semantic_visitor
~~~~~~~~~~~~~~~~~~~~~~~~~~
SemanticVisitor: walks the raw parser AST, validates token sequences against
the DSL schema, coerces values to strong Python types, and produces a
ValidatedConf tree.

Responsibilities
----------------
  - Structural validation: are the right keywords present? are required
    params present? are enum values in range?
  - Type coercion: raw token strings → ipaddress objects, booleans, ints,
    TsigAlgorithmValue, AddressMatchElement, AclRef, KeyRef etc.
  - Error collection: all problems are collected in self.errors; the visitor
    never raises. The caller always receives a (possibly partial) typed tree.

NOT responsible for
-------------------
  - Cross-reference resolution (AclRef → AclStatement etc) — that is the
    TransformationVisitor's job since it requires the full domain picture.
  - Instantiating domain dataclasses — no OptionsStatement, ZoneStatement etc
    are created here.

Public API
----------
    from isc.named.semantic_visitor import SemanticVisitor, ValidationError
    from isc.named.named_schema     import NAMED_CONF
    from isc.named.parser           import parse

    conf   = parse(text)
    sv     = SemanticVisitor(NAMED_CONF, strict=False)
    result = sv.visit(conf)          # → ValidatedConf

    for err in sv.errors:
        print(err)

Token flow
----------
Tokens are passed as a list. Each resolution method returns
(value, remaining_tokens) so the cursor advances without mutation.
"""

from __future__ import annotations

import base64 as _base64
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from isc.named.lexer  import Token, Word, Number, String
from isc.named.parser import Conf, Statement, Block, Negated

from isc.named.dsl import (
    IpAddressType, IpPrefixType, BooleanType, Integer, FixedPoint,
    Percentage, Size, StringType, EnumType, Duration, RrTypeList,
    TsigAlgorithm, Base64, Unlimited,
    AclReference, KeyReference, TlsReference, ViewReference,
    Arg, Keyword, Optional, Negatable, Wildcard, Deprecated,
    Multiple, OneOf, ExclusiveOf, Variadic, ListOf, Context,
    StatementDef,
)
from isc.named.typed_ast import (
    TsigAlgorithmValue, AddressMatchElement,
    AclRef, KeyRef, TlsRef, ViewRef,
    ValidatedParam, ValidatedStatement, ValidatedConf,
)

__all__ = [
    "SemanticVisitor",
    "ValidationError",
    "Severity",
]


# ---------------------------------------------------------------------------
# Severity and ValidationError
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
# Duration parsing helpers
# ---------------------------------------------------------------------------

_TTL_RE = re.compile(
    r'^(?:(\d+)[wW])?(?:(\d+)[dD])?(?:(\d+)[hH])?(?:(\d+)[mM])?(?:(\d+)[sS]?)?$'
)
_TTL_FACTORS = (604800, 86400, 3600, 60, 1)

# ISO 8601 durations come in two mutually exclusive forms:
#
#   Week form:    P<n>W              — weeks only, no other date units
#   General form: P[nY][nM][nD][T[nH][nM][nS]]  — no W allowed
#
# The bare "P" (zero duration) is also valid per the ISC documentation.

_ISO_WEEK_RE = re.compile(r'^[Pp](\d+)[Ww]$')

_ISO_GENERAL_RE = re.compile(
    r'^[Pp]'
    r'(?:(\d+)[Yy])?'
    r'(?:(\d+)[Mm])?'
    r'(?:(\d+)[Dd])?'
    r'(?:[Tt]'
    r'(?:(\d+)[Hh])?'
    r'(?:(\d+)[Mm])?'
    r'(?:(\d+)[Ss])?'
    r')?$'
)
_ISO_GENERAL_FACTORS = (365 * 86400, 30 * 86400, 86400, 3600, 60, 1)

_TSIG_BASE = frozenset({
    "hmac-md5", "hmac-sha1",   "hmac-sha224",
    "hmac-sha256", "hmac-sha384", "hmac-sha512",
    "gss-tsig",
})
_TSIG_NO_TRUNC = frozenset({"hmac-md5", "gss-tsig"})

_BUILTIN_ACLS = frozenset({"any", "none", "localhost", "localnets"})


def _parse_ttl(s: str) -> int | None:
    m = _TTL_RE.fullmatch(s.strip())
    if not m or not any(m.groups()):
        return None
    return sum(int(g) * f for g, f in zip(m.groups(), _TTL_FACTORS) if g)


def _parse_iso8601(s: str) -> int | None:
    """
    Parse an ISO 8601 duration string to seconds.

    Valid forms:
      P           — zero duration (ISC extension)
      P<n>W       — weeks only; W cannot appear with Y, M, D or T units
      P[nY][nM][nD][T[nH][nM][nS]]  — general form without W

    Returns None if the string does not match any valid form.
    """
    upper = s.strip().upper()

    if upper == "P":
        return 0

    # Week form: PnW — no other units permitted
    m = _ISO_WEEK_RE.fullmatch(s.strip())
    if m:
        return int(m.group(1)) * 7 * 86400

    # General form: no W unit
    m = _ISO_GENERAL_RE.fullmatch(s.strip())
    if not m:
        return None
    # Guard: at least one group must be present (bare "P" handled above)
    if not any(m.groups()):
        return None
    return sum(int(g) * f for g, f in zip(m.groups(), _ISO_GENERAL_FACTORS) if g)


# ---------------------------------------------------------------------------
# SemanticVisitor
# ---------------------------------------------------------------------------

class SemanticVisitor:
    """
    Validates a raw named.conf AST against a DSL schema and produces
    a ValidatedConf tree of grammar-shaped, strongly-typed nodes.

    Parameters
    ----------
    schema : Context
        The top-level schema. Typically NAMED_CONF from isc.named.named_schema.
    strict : bool
        If True unknown keywords are errors. If False (default) they
        produce a WARNING and the statement is included as-is.
    """

    def __init__(self, schema: Context, strict: bool = False) -> None:
        self._schema = schema
        self._strict = strict
        self.errors: list[ValidationError] = []

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def visit(self, conf: Conf) -> ValidatedConf:
        """Validate the root Conf node and return a ValidatedConf."""
        result = ValidatedConf()
        result.body = self._visit_context_body(conf, self._schema)
        return result

    # ------------------------------------------------------------------
    # Error helpers
    # ------------------------------------------------------------------

    def _err(
        self,
        message:  str,
        node:     Any = None,
        severity: Severity = Severity.ERROR,
        context:  str = "",
    ) -> None:
        line = col = None
        span = getattr(node, "span", None)
        if span:
            line, col = span.line, span.col
        self.errors.append(ValidationError(
            message=message, severity=severity,
            line=line, col=col, context=context,
        ))

    # ------------------------------------------------------------------
    # Context body — produces list[ValidatedStatement]
    # ------------------------------------------------------------------

    def _visit_context_body(
        self,
        node:   Conf | Block,
        schema: Context,
    ) -> list[ValidatedStatement]:
        """
        Walk the body of a Conf or Block, match each child statement against
        the schema, and return a list of ValidatedStatements.

        Every entry in a Context is a StatementDef (or a Multiple /
        ExclusiveOf / Deprecated wrapper around one). Presence is always
        implicit — if the keyword appears the statement is validated, if not
        the field stays at its default in the domain object.
        """
        unique_map:   dict[str, StatementDef]               = {}
        multiple_map: dict[str, tuple[StatementDef, str]]   = {}
        excl_groups:  list[tuple[int, dict[str, StatementDef]]] = []

        for i, entry in enumerate(schema.statements):
            if isinstance(entry, ExclusiveOf):
                group = {opt.keyword: opt for opt in entry.options
                         if isinstance(opt, StatementDef)}
                excl_groups.append((i, group))
                continue

            sdef, is_multiple, multiple_attr = self._unwrap_schema_entry(entry)
            if sdef is None:
                continue
            if is_multiple:
                attr = multiple_attr or sdef.keyword.replace("-", "_")
                multiple_map[sdef.keyword] = (sdef, attr)
            else:
                unique_map[sdef.keyword] = sdef

        results:        list[ValidatedStatement] = []
        seen_unique:    set[str]                 = set()
        seen_exclusive: dict[int, str]           = {}

        for child in node.body:
            negated = isinstance(child, Negated)
            inner   = child.inner if negated else child

            if not isinstance(inner, Statement):
                self._err(f"Expected a statement, got {type(inner).__name__}", child)
                continue

            keyword = self._peek_keyword(inner)
            if not keyword:
                self._err("Statement has no keyword", inner)
                continue

            # Deprecated warning
            for entry in schema.statements:
                if (isinstance(entry, Deprecated)
                        and hasattr(entry.inner, "keyword")
                        and entry.inner.keyword == keyword):
                    self._err(f"'{keyword}' is deprecated",
                              inner, severity=Severity.WARNING)
                    break

            # Resolve which StatementDef matches
            sdef     = None
            group_id = None

            if keyword in unique_map:
                sdef = unique_map[keyword]
                if keyword in seen_unique:
                    self._err(f"'{keyword}' may only appear once", inner)
                    continue
                seen_unique.add(keyword)

            elif keyword in multiple_map:
                sdef, _attr = multiple_map[keyword]

            else:
                for gid, group in excl_groups:
                    if keyword in group:
                        sdef     = group[keyword]
                        group_id = gid
                        break

            if sdef is None:
                sev = Severity.ERROR if self._strict else Severity.WARNING
                self._err(f"Unknown keyword '{keyword}'", inner, severity=sev)
                results.append(ValidatedStatement(
                    keyword=keyword, negated=negated, raw=inner,
                ))
                continue

            if group_id is not None:
                if group_id in seen_exclusive:
                    self._err(
                        f"Only one of the exclusive options is allowed, "
                        f"already saw '{seen_exclusive[group_id]}', "
                        f"got '{keyword}'",
                        inner,
                    )
                    continue
                seen_exclusive[group_id] = keyword

            results.append(self._visit_statement(inner, sdef, negated=negated))

        return results

    def _unwrap_schema_entry(
        self, entry: Any
    ) -> tuple[StatementDef | None, bool, str | None]:
        """
        Returns (sdef, is_multiple, multiple_attr).
        Handles Multiple, Deprecated, and bare StatementDef.
        """
        if isinstance(entry, Multiple):
            inner = entry.inner
            if isinstance(inner, Deprecated):
                inner = inner.inner
            if isinstance(inner, StatementDef):
                return inner, True, entry.attr
            return None, False, None

        if isinstance(entry, Deprecated):
            inner = entry.inner
            if isinstance(inner, StatementDef):
                return inner, False, None
            return None, False, None

        if isinstance(entry, StatementDef):
            return entry, False, None

        if isinstance(entry, ExclusiveOf):
            return None, False, None   # handled separately

        return None, False, None

    # ------------------------------------------------------------------
    # Statement — produces ValidatedStatement
    # ------------------------------------------------------------------

    def _visit_statement(
        self,
        node:    Statement,
        sdef:    StatementDef,
        negated: bool = False,
    ) -> ValidatedStatement:
        """Resolve a statement's params and return a ValidatedStatement."""
        # For keyworded statements skip the keyword token itself
        tokens = list(node.values)
        if sdef.keyword:
            tokens = tokens[1:]

        params, body = self._resolve_params(tokens, sdef.params, node)

        return ValidatedStatement(
            keyword=sdef.keyword or self._peek_keyword(node),
            params=params,
            body=body,
            negated=negated,
            raw=node,
        )

    def _resolve_params(
        self,
        tokens: list,
        specs:  tuple,
        node:   Any,
    ) -> tuple[list[ValidatedParam], list[ValidatedStatement]]:
        """
        Walk the spec list, consuming tokens and producing ValidatedParams.
        Returns (params, body_statements).
        """
        params: list[ValidatedParam]      = []
        body:   list[ValidatedStatement]  = []

        for spec in specs:
            result, tokens = self._resolve_param(spec, tokens, node)

            if result is None:
                continue

            # Context resolution returns list[ValidatedStatement] → body
            if isinstance(result, list) and (
                not result or isinstance(result[0], ValidatedStatement)
            ):
                body.extend(result)
                continue

            if isinstance(result, ValidatedParam):
                if not result.name.startswith("_"):
                    params.append(result)
                continue

            if isinstance(result, ValidatedStatement):
                body.append(result)
                continue

            # Fallback: wrap scalar in a param if possible
            if hasattr(spec, 'name'):
                params.append(ValidatedParam(
                    name=spec.name, value=result, type_name=type(result).__name__,
                ))

        if tokens:
            self._err(
                "Unexpected tokens: "
                + ", ".join(repr(getattr(t, "raw", t)) for t in tokens),
                node,
            )

        return params, body

    # ------------------------------------------------------------------
    # Param resolution — peel one wrapper layer
    # ------------------------------------------------------------------

    def _resolve_param(
        self,
        spec:   Any,
        tokens: list,
        node:   Any,
    ) -> tuple[Any, list]:
        """
        Peel the outermost DSL wrapper and delegate.
        Returns (result, remaining_tokens).
        result may be: ValidatedParam | list[ValidatedStatement] |
                       dict (from Context) | None
        """
        if isinstance(spec, Optional):
            return self._resolve_optional(spec, tokens, node)

        if isinstance(spec, Keyword):
            return self._resolve_keyword(spec, tokens, node)

        if isinstance(spec, Negatable):
            return self._resolve_param(spec.inner, tokens, node)

        if isinstance(spec, Wildcard):
            return self._resolve_wildcard(spec, tokens, node)

        if isinstance(spec, Variadic):
            return self._resolve_variadic(spec, tokens, node)

        if isinstance(spec, Arg):
            return self._resolve_arg(spec, tokens, node)

        if isinstance(spec, ListOf):
            block = self._extract_block(tokens)
            if block is None:
                self._err("Expected a block '{ }'", node)
                return None, tokens
            tokens = [t for t in tokens if t is not block]
            return self._resolve_list_of(block, spec, node), tokens

        if isinstance(spec, Context):
            block = self._extract_block(tokens)
            if block is None:
                self._err("Expected a block '{ }'", node)
                return None, tokens
            tokens = [t for t in tokens if t is not block]
            body = self._visit_context_body(block, spec)
            return body, tokens

        self._err(f"Unhandled spec type {type(spec).__name__}", node)
        return None, tokens

    def _resolve_optional(
        self, spec: Optional, tokens: list, node: Any
    ) -> tuple[Any, list]:
        # Guard: if next token is a Block and inner expects only scalars, skip
        if tokens and isinstance(tokens[0], Block):
            inner = spec.inner
            if isinstance(inner, Keyword):
                inner = inner.inner
            if isinstance(inner, Arg):
                all_structural = all(
                    isinstance(t, (ListOf, Context)) for t in inner.types
                )
                if not all_structural:
                    return None, tokens

        result, remaining = self._resolve_param(spec.inner, tokens, node)
        if result is None:
            return None, tokens
        return result, remaining

    def _resolve_keyword(
        self, spec: Keyword, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """Scan for sentinel word, consume it, resolve what follows."""
        inner    = spec.inner
        sentinel = self._arg_name(inner)

        sentinel_idx = next(
            (i for i, t in enumerate(tokens)
             if isinstance(t, Word) and t.value == sentinel),
            None,
        )
        if sentinel_idx is None:
            return None, tokens

        tokens = list(tokens)
        tokens.pop(sentinel_idx)

        inner_spec = inner if isinstance(inner, Arg) else inner.inner
        return self._resolve_param(inner_spec, tokens, node)

    def _resolve_wildcard(
        self, spec: Wildcard, tokens: list, node: Any
    ) -> tuple[Any, list]:
        if tokens and isinstance(tokens[0], Word) and tokens[0].value == "*":
            name = self._arg_name(spec.inner)
            return ValidatedParam(
                name=name, value=None, type_name="Wildcard", raw=tokens[0]
            ), tokens[1:]
        return self._resolve_param(spec.inner, tokens, node)

    def _resolve_variadic(
        self, spec: Variadic, tokens: list, node: Any
    ) -> tuple[list, list]:
        results = []
        while tokens and not isinstance(tokens[0], Block):
            coerced, err = self._coerce(tokens[0], spec.inner)
            if err:
                break
            results.append(coerced)
            tokens = tokens[1:]
        name = self._arg_name(spec.inner) if isinstance(spec.inner, Arg) else "values"
        return ValidatedParam(name=name, value=results, type_name="Variadic"), tokens

    def _resolve_arg(
        self, spec: Arg, tokens: list, node: Any
    ) -> tuple[Any, list]:
        """Try each type in spec.types, return the first successful coercion."""
        if not tokens:
            self._err(f"Missing value for '{spec.name}'", node)
            return None, tokens

        tok = tokens[0]

        for type_spec in spec.types:
            if isinstance(type_spec, ListOf):
                if isinstance(tok, Block):
                    result = self._resolve_list_of(tok, type_spec, node)
                    return ValidatedParam(
                        name=spec.name, value=result,
                        type_name="ListOf", raw=tok,
                    ), tokens[1:]
                continue

            if isinstance(type_spec, Context):
                if isinstance(tok, Block):
                    body = self._visit_context_body(tok, type_spec)
                    return ValidatedParam(
                        name=spec.name, value=body,
                        type_name="Context", raw=tok,
                    ), tokens[1:]
                continue

            if isinstance(type_spec, OneOf):
                for option in type_spec.options:
                    if isinstance(option, Keyword):
                        sentinel = self._arg_name(option)
                        if (isinstance(tok, Word)
                                and tok.value == sentinel
                                and len(tokens) > 1):
                            inner_arg = option.inner
                            result, remaining = self._resolve_arg(
                                inner_arg, tokens[1:], node
                            )
                            if result is not None:
                                return ValidatedParam(
                                    name=spec.name,
                                    value=result.value if isinstance(result, ValidatedParam) else result,
                                    type_name="OneOf",
                                    raw=tok,
                                ), remaining
                        continue
                    coerced, err = self._coerce(tok, option)
                    if err is None:
                        return ValidatedParam(
                            name=spec.name, value=coerced,
                            type_name="OneOf", raw=tok,
                        ), tokens[1:]
                continue

            coerced, err = self._coerce(tok, type_spec)
            if err is None:
                return ValidatedParam(
                    name=spec.name, value=coerced,
                    type_name=type(type_spec).__name__, raw=tok,
                ), tokens[1:]

        self._err(
            f"'{spec.name}': expected "
            + " or ".join(type(t).__name__ for t in spec.types)
            + f", got {getattr(tok, 'raw', repr(tok))!r}",
            tok,
        )
        return None, tokens[1:]

    # ------------------------------------------------------------------
    # ListOf — produces a list of coerced values or ValidatedStatements
    # ------------------------------------------------------------------

    def _resolve_list_of(
        self, block: Block, spec: ListOf, node: Any
    ) -> list:
        results = []
        for child in block.body:
            negated = isinstance(child, Negated)
            inner   = child.inner if negated else child
            result  = self._resolve_list_element(inner, spec, negated, node)
            if result is not None:
                results.append(result)
        return results

    def _resolve_list_element(
        self, node: Any, spec: ListOf, negated: bool, parent: Any
    ) -> Any:
        inner = spec.inner

        if isinstance(inner, Negatable):
            inner = inner.inner

        if isinstance(inner, StatementDef):
            if not isinstance(node, Statement):
                self._err(f"Expected a statement", node)
                return None
            keyword = self._peek_keyword(node) if inner.keyword else None
            if inner.keyword and keyword != inner.keyword:
                self._err(
                    f"Expected '{inner.keyword}', got '{keyword}'", node,
                )
                return None
            return self._visit_statement(node, inner, negated=negated)

        if isinstance(inner, OneOf):
            return self._resolve_one_of_element(node, inner, negated, parent)

        if isinstance(inner, Arg):
            if isinstance(node, Statement):
                values = list(node.values)
                if len(values) == 1:
                    result, _ = self._resolve_arg(inner, values, node)
                    if isinstance(result, ValidatedParam):
                        val = result.value
                        if negated and isinstance(val, AddressMatchElement):
                            val.negated = True
                        return val
                # Multi-token — try each type against the full statement
                for type_spec in inner.types:
                    coerced, err = self._coerce(node, type_spec)
                    if err is None:
                        return coerced
            self._err(f"Could not resolve '{inner.name}'", node)
            return None

        # Bare type spec
        if isinstance(node, Statement):
            values = list(node.values)
            if len(values) > 1:
                coerced, err = self._coerce(node, inner)
            elif len(values) == 1:
                coerced, err = self._coerce(values[0], inner)
            else:
                return None
            if err:
                self._err(err, node)
                return None
            if negated and isinstance(coerced, AddressMatchElement):
                coerced.negated = True
            return coerced

        return None

    def _resolve_one_of_element(
        self, node: Any, spec: OneOf, negated: bool, parent: Any
    ) -> Any:
        for option in spec.options:
            if isinstance(option, StatementDef):
                if not isinstance(node, Statement):
                    continue
                keyword = self._peek_keyword(node)
                if keyword == option.keyword:
                    return self._visit_statement(node, option, negated=negated)
                continue
            if isinstance(node, Statement) and len(node.values) == 1:
                coerced, err = self._coerce(node.values[0], option)
                if err is None:
                    return coerced
            elif isinstance(node, (Word, String, Number)):
                coerced, err = self._coerce(node, option)
                if err is None:
                    return coerced
        self._err(
            f"No matching OneOf option for "
            f"{getattr(node, 'raw', repr(node))!r}",
            node,
        )
        return None

    # ------------------------------------------------------------------
    # Coercion — token/node → strongly typed Python value
    # ------------------------------------------------------------------

    def _coerce(self, node: Any, type_spec: Any) -> tuple[Any, str | None]:
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

    def _coerce_ip_address(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected IP address, got {type(node).__name__}"
        if node.value == "*":
            return node.value, None
        try:
            return ipaddress.ip_address(node.value), None
        except ValueError:
            return None, f"{node.value!r} is not a valid IP address"

    def _coerce_ip_prefix(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected IP prefix, got {type(node).__name__}"
        if "/" not in node.value:
            return None, f"{node.value!r} is not a valid IP prefix"
        try:
            return ipaddress.ip_network(node.value, strict=False), None
        except ValueError:
            return None, f"{node.value!r} is not a valid IP prefix"

    def _coerce_boolean(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, Number)):
            return None, f"expected boolean, got {type(node).__name__}"
        v = str(node.value).lower()
        if v in ("yes", "true", "1"):
            return True, None
        if v in ("no", "false", "0"):
            return False, None
        return None, f"{node.raw!r} is not a valid boolean"

    def _coerce_integer(self, node: Any, spec: Integer) -> tuple[Any, str | None]:
        if not isinstance(node, Number):
            return None, f"expected integer, got {type(node).__name__}"
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
            return None, f"expected fixed point, got {type(node).__name__}"
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
            return None, f"expected percentage, got {type(node).__name__}"
        m = re.fullmatch(r'(\d+)%', node.value)
        if not m:
            return None, f"{node.value!r} is not a valid percentage"
        v = int(m.group(1))
        if spec.min is not None and v < spec.min:
            return None, f"{v}% below minimum {spec.min}%"
        if spec.max is not None and v > spec.max:
            return None, f"{v}% exceeds maximum {spec.max}%"
        return v, None

    def _coerce_size(self, node: Any, spec: Size) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String, Number)):
            return None, f"expected size, got {type(node).__name__}"
        m = re.fullmatch(r'(\d+)([kmgKMG])?', node.raw)
        if not m:
            return None, f"{node.raw!r} is not a valid size"
        v = int(m.group(1)) * {"k": 1024, "m": 1024**2, "g": 1024**3}.get(
            (m.group(2) or "").lower(), 1
        )
        if spec.min is not None and v < spec.min:
            return None, f"{v} below minimum {spec.min}"
        if spec.max is not None and v > spec.max:
            return None, f"{v} exceeds maximum {spec.max}"
        return v, None

    def _coerce_duration(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String, Number)):
            return None, f"expected duration, got {type(node).__name__}"
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
        return None, f"{s!r} is not a valid duration"

    def _coerce_string(self, node: Any) -> tuple[Any, str | None]:
        if isinstance(node, (String, Word)):
            return node.value, None
        return None, f"expected string, got {type(node).__name__}"

    def _coerce_enum(self, node: Any, spec: EnumType) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected one of {spec.values}"
        if node.value not in spec.values:
            return None, f"{node.value!r} not in {spec.values}"
        return node.value, None

    def _coerce_rr_type_list(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected RR type list, got {type(node).__name__}"
        if node.value.upper() == "ANY":
            return ["ANY"], None
        return [node.value.upper()], None

    def _coerce_tsig_algorithm(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, (Word, String)):
            return None, f"expected algorithm name, got {type(node).__name__}"
        value = node.value.lower()
        parts = value.rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            base, trunc = parts[0], int(parts[1])
            if base not in _TSIG_BASE:
                return None, f"{node.value!r} is not a valid TSIG algorithm"
            if base in _TSIG_NO_TRUNC:
                return None, f"{base} does not support truncation"
            return TsigAlgorithmValue(base=base, truncation=trunc), None
        if value not in _TSIG_BASE:
            return None, f"{node.value!r} is not a valid TSIG algorithm"
        return TsigAlgorithmValue(base=value, truncation=None), None

    def _coerce_base64(self, node: Any) -> tuple[Any, str | None]:
        if not isinstance(node, String):
            return None, f"expected quoted Base64 string, got {type(node).__name__}"
        stripped = node.value.replace(" ", "").replace("\n", "")
        try:
            _base64.b64decode(stripped, validate=True)
            return stripped, None
        except Exception:
            return None, f"{node.value!r} is not valid Base64"

    def _coerce_unlimited(self, node: Any) -> tuple[Any, str | None]:
        if isinstance(node, Word) and node.value == "unlimited":
            return None, None  # None signals no limit
        return None, f"expected 'unlimited', got {getattr(node, 'raw', node)!r}"

    def _coerce_reference(
        self, node: Any, kind: str
    ) -> tuple[Any, str | None]:
        """
        Coerce a reference. Accepts two forms:
          - Bare token:           "myacl", "mykey"
          - Statement with key:  key "mykey"
        Returns the appropriate Ref object (AclRef, KeyRef, etc).
        """
        _ref_classes = {
            "acl": AclRef, "key": KeyRef,
            "tls": TlsRef, "view": ViewRef,
        }
        cls = _ref_classes[kind]

        if isinstance(node, (Word, String)):
            return cls(node.value), None

        if isinstance(node, Statement):
            values = list(node.values)
            if (len(values) == 2
                    and isinstance(values[0], Word)
                    and values[0].value == kind
                    and isinstance(values[1], (Word, String))):
                return cls(values[1].value), None
            if len(values) == 1 and isinstance(values[0], (Word, String)):
                return cls(values[0].value), None
            return None, f"expected {kind} reference, got {node!r}"

        return None, f"expected {kind} reference, got {type(node).__name__}"

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _peek_keyword(self, node: Statement) -> str:
        for v in node.values:
            if isinstance(v, (Word, String)):
                return v.value
        return ""

    def _arg_name(self, spec: Any) -> str:
        if isinstance(spec, Arg):
            return spec.name
        if hasattr(spec, "inner"):
            return self._arg_name(spec.inner)
        if isinstance(spec, StatementDef):
            return spec.keyword
        return ""

    def _extract_block(self, tokens: list) -> Block | None:
        for t in tokens:
            if isinstance(t, Block):
                return t
        return None
