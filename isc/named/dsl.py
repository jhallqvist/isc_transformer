from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Types
# Describe what kind of value is expected at a given position.
# No logic — pure descriptors consumed by the visitor.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IpAddressType:
    """A single IPv4 or IPv6 address."""

@dataclass(frozen=True)
class IpPrefixType:
    """An IPv4 or IPv6 subnet in CIDR notation."""

@dataclass(frozen=True)
class BooleanType:
    """An ISC boolean: yes/no, true/false or 1/0."""

@dataclass(frozen=True)
class Duration:
    """
    An ISC duration. Accepts all three formats:
      - plain integer (seconds)
      - TTL shorthand: 1W, 3d12h
      - ISO 8601: P3M10D, pt15m, P (zero)
    """

@dataclass(frozen=True)
class Integer:
    """A plain integer with optional range constraints."""
    min: int | None = None
    max: int | None = None

@dataclass(frozen=True)
class FixedPoint:
    """
    An ISC fixed point value: one to five digits followed by
    '.' and exactly two digits. e.g. 1.50, 100.00
    """
    min: float | None = None
    max: float | None = None

@dataclass(frozen=True)
class Percentage:
    """A numeric string followed by '%'. e.g. 50%"""
    min: int | None = None
    max: int | None = None

@dataclass(frozen=True)
class Size:
    """A numeric string followed by k, m or g."""
    min: int | None = None
    max: int | None = None

@dataclass(frozen=True)
class StringType:
    """A quoted or bare string value."""

@dataclass(frozen=True)
class EnumType:
    """One of a fixed set of bare word values."""
    values: tuple[str, ...]

@dataclass(frozen=True)
class TsigAlgorithm:
    """
    An ISC TSIG algorithm name with optional truncation suffix.
    Base algorithms: hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256,
                     hmac-sha384, hmac-sha512, gss-tsig.
    Truncation suffix: -<integer> appended to the algorithm name.
    e.g. hmac-sha256-80, hmac-sha512-128.
    Truncation is not valid for hmac-md5 or gss-tsig.
    """

@dataclass(frozen=True)
class Base64:
    """
    A quoted string whose value must be valid Base64.
    Padding with '=' is accepted. Whitespace within the
    encoded string is ignored per ISC convention.
    """

@dataclass(frozen=True)
class RrTypeList:
    """
    A DNS resource record type list.
    Accepts ANY, a single RR type, or a space-separated list of RR types.
    """

# ---------------------------------------------------------------------------
# Reference types
# Carry the kind of definition they refer to.
# Resolved in the visitor's reconciliation step after the full tree is walked.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AclReference:
    """A reference to a defined acl statement."""

@dataclass(frozen=True)
class KeyReference:
    """A reference to a defined key statement."""

@dataclass(frozen=True)
class TlsReference:
    """A reference to a defined tls statement."""

@dataclass(frozen=True)
class ViewReference:
    """A reference to a defined view statement."""

# ---------------------------------------------------------------------------
# Directives
# Instruct the visitor how to handle Args or Statements.
# No logic — pure descriptors consumed by the visitor.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Arg:
    """
    A single named parameter slot accepting one or more types.

    name    the attribute name on the target dataclass, and the keyword
            sentinel when wrapped in Keyword.
    types   one or more type descriptors tried in order until one matches.
            A single type is the common case. Multiple types express a
            union of acceptable values at this position.
    """
    name:  str
    types: tuple[Any, ...]

    def __init__(self, name: str, *types: Any) -> None:
        object.__setattr__(self, "name",  name)
        object.__setattr__(self, "types", types)

@dataclass(frozen=True)
class Keyword:
    """
    Enforces the presence of Arg.name as a sentinel word before the value.
    The sentinel word is consumed and not included in the typed output.
    Unless wrapped in Optional the sentinel must be present.
    """
    inner: Any   # Arg or Optional(Arg)

@dataclass(frozen=True)
class Optional:
    """
    Marks an Arg or Keyword as optional.
    If absent the visitor resolves the Arg.name to None without error.
    """
    inner: Any

@dataclass(frozen=True)
class Negatable:
    """
    Marks that the inner element may be preceded by '!' in the source.
    Without this wrapper a Negated AST node at this position is an error.
    The resolved typed node carries negation as a boolean on the dataclass.
    """
    inner: Any

@dataclass(frozen=True)
class Wildcard:
    """
    When the token value is '*' matches without coercing through the inner
    type, resolving to a sentinel value the visitor substitutes instead.
    Otherwise the inner Arg type is used normally.
    """
    inner: Any

@dataclass(frozen=True)
class Deprecated:
    """
    Marks a Statement as deprecated.
    The visitor registers a warning but does not raise an error.
    Processing continues normally through the inner statement.
    """
    inner: Any

@dataclass(frozen=True)
class Multiple:
    """
    Allows one or more occurrences of the inner Statement within its context.
    Uniqueness is the default assumption — Multiple is the explicit exception.
    """
    inner: Any

@dataclass(frozen=True)
class OneOf:
    """
    Value-level union. Used inside Arg.types to express that a single
    token position accepts multiple possible types. The visitor tries
    each option in order and uses the first that coerces successfully.
    """
    options: tuple[Any, ...]

    def __init__(self, *options: Any) -> None:
        object.__setattr__(self, "options", options)

@dataclass(frozen=True)
class ExclusiveOf:
    """
    Statement-level mutual exclusion. Used inside Context to express
    that exactly one of the given StatementDefs may appear in the body.
    The visitor enforces that only one is present and emits an error
    if a second one is encountered.
    """
    options: tuple[Any, ...]

    def __init__(self, *options: Any) -> None:
        object.__setattr__(self, "options", options)

@dataclass(frozen=True)
class AnyOrder:
    """
    A set of keyword/value args that may appear in any order.
    Each inner element is matched by its keyword sentinel regardless
    of position. All non-Optional elements must appear exactly once.
    """
    inner: tuple[Any, ...]

    def __init__(self, *inner: Any) -> None:
        object.__setattr__(self, "inner", inner)

@dataclass(frozen=True)
class Variadic:
    """
    Consumes all remaining tokens of the inner type.
    Must be the last element in its containing Block or param list.
    Resolves to a list of coerced values.
    """
    inner: Any

@dataclass(frozen=True)
class ListOf:
    """
    Expects a brace-enclosed AST Block node.
    Resolves to a homogeneous list — use for address match lists,
    key lists and any other repeated value sequences.
    """
    inner: Any
    node_class: type

@dataclass(frozen=True)
class Context:
    """
    Expects a sequence of statements and resolves them as named attributes
    on the target node_class dataclass.

    Applies to two AST node types:
      - Conf: the top level sequence of statements in a named.conf file.
              No braces are present in the source — the sequence is implicit.
      - Block: a brace-enclosed sequence of statements nested inside another
               statement, e.g. options { }, zone { }, key { }.

    The distinction between Conf and Block is a parser-level detail — from
    the schema's perspective both are sequences of statements that resolve
    to a typed dataclass. The visitor dispatches on the AST node type it
    receives and extracts the body in either case.

    Use Context when the result should be a structured dataclass with named
    attributes. Use Block when the result should be a homogeneous list.
    """
    statements: tuple[Any, ...]

    def __init__(self, *statements: Any) -> None:
        object.__setattr__(self, "statements", statements)

# ---------------------------------------------------------------------------
# Statement and schema definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StatementDef:
    """
    Defines the shape of one named statement.

    keyword     the first token that identifies this statement
    params      ordered sequence of Arg/Keyword/Optional/Block/Context slots
    node_class  the typed dataclass to instantiate on successful validation
    """
    keyword:    str
    params:     tuple[Any, ...]
    node_class: type

    def __init__(self, keyword: str, node_class: type, *params: Any) -> None:
        object.__setattr__(self, "keyword",    keyword)
        object.__setattr__(self, "node_class", node_class)
        object.__setattr__(self, "params",     params)
