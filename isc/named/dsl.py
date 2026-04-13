"""
isc.named.dsl
~~~~~~~~~~~~~
DSL types for describing the ISC named.conf schema.

Two categories:

  Types       — describe what kind of value is expected at a position.
                Pure descriptors, no logic.

  Directives  — instruct the visitor how to handle Args or Statements.
                Pure descriptors, no logic.

Convention
----------
  - Absence of Optional means required.
  - Absence of Multiple means unique (may appear only once in its context).
  - ListOf implies one or more — Multiple and Variadic are not needed inside it.
  - Block is the parser AST node type. ListOf and Context are the DSL
    constructs that describe what to do with a brace-enclosed body.
  - node_class is intentionally absent from StatementDef and ListOf.
    The mapping from grammar constructs to domain objects belongs in the
    TransformationVisitor, not in the schema.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IpAddressType:
    """A single IPv4 or IPv6 address."""


@dataclass(frozen=True)
class IpPrefixType:
    """An IPv4 or IPv6 subnet in CIDR notation e.g. 10.0.0.0/8."""


@dataclass(frozen=True)
class BooleanType:
    """An ISC boolean: yes/no, true/false or 1/0."""


@dataclass(frozen=True)
class Integer:
    """A plain integer with optional range constraints."""
    min: int | None = None
    max: int | None = None


@dataclass(frozen=True)
class FixedPoint:
    """
    An ISC fixed point value: one to five digits followed by '.' and
    exactly two digits. e.g. 1.50, 100.00
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
    """
    A numeric string followed by k, m or g representing
    kilobytes, megabytes or gigabytes respectively.
    Constraints are in bytes after suffix expansion.
    """
    min: int | None = None
    max: int | None = None


@dataclass(frozen=True)
class StringType:
    """A quoted or bare string value."""


@dataclass(frozen=True)
class NameType:
    """
    An ISC object name — the identifier used for acl, key, zone, view etc.
    Accepts Word, String, and Number tokens since BIND allows any token type
    as an object name (e.g. 'key 1 { ... }' is valid).
    Coerces to str.
    """


@dataclass(frozen=True)
class IscClassType:
    """
    An ISC DNS class identifier.
    Accepts the full names and their standard abbreviations,
    case-insensitively:
      IN  / INET  — Internet (default)
      CH  / CHAOS — Chaosnet
      HS  / HESIOD
      ANY
    Coerces to the canonical uppercase short form (IN, CH, HS, ANY).
    """


@dataclass(frozen=True)
class EnumType:
    """One of a fixed set of bare word values."""
    values: tuple[str, ...]

    def __init__(self, *values: str) -> None:
        object.__setattr__(self, "values", values)


@dataclass(frozen=True)
class Duration:
    """
    An ISC duration. Always accepts all three formats:
      - plain integer (seconds)
      - TTL shorthand: 1W, 3d12h (case-insensitive)
      - ISO 8601:      P3M10D, pt15m, P (zero) (case-insensitive)
    """


@dataclass(frozen=True)
class RrTypeList:
    """
    A DNS resource record type list.
    Accepts ANY, a single RR type name, or a space-separated list.
    """


@dataclass(frozen=True)
class TsigAlgorithm:
    """
    An ISC TSIG algorithm name with optional truncation suffix.
    Base algorithms:
        hmac-md5, hmac-sha1, hmac-sha224, hmac-sha256,
        hmac-sha384, hmac-sha512, gss-tsig
    Truncation suffix: -<integer> appended to the base name.
        e.g. hmac-sha256-80, hmac-sha512-128
    Truncation is not valid for hmac-md5 or gss-tsig.
    Coerces to TsigAlgorithmValue(base, truncation).
    """


@dataclass(frozen=True)
class Base64:
    """
    A quoted string whose content must be valid Base64.
    Padding with '=' is accepted.
    Whitespace within the encoded string is ignored per ISC convention.
    """


@dataclass(frozen=True)
class Unlimited:
    """
    The bare word 'unlimited' used in place of a numeric value.
    Coerces to None to signal no limit.
    """


# ---------------------------------------------------------------------------
# Reference types
# Coerced to named reference objects (AclRef, KeyRef etc) by the
# SemanticVisitor. Resolved against definitions by the TransformationVisitor.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AclReference:
    """
    A reference to a defined acl statement.
    Coerces to AclRef(name).
    """


@dataclass(frozen=True)
class KeyReference:
    """
    A reference to a defined key statement.
    Accepts two forms depending on context:
      - Statement form:  key "name";   (in address match lists)
      - Bare name form:  "name";       (in keys { } blocks)
    The visitor distinguishes the two from the AST node type received.
    Coerces to KeyRef(name).
    """


@dataclass(frozen=True)
class TlsReference:
    """
    A reference to a defined tls statement.
    Coerces to TlsRef(name).
    """


@dataclass(frozen=True)
class ViewReference:
    """
    A reference to a defined view statement.
    Coerces to ViewRef(name).
    """


# ---------------------------------------------------------------------------
# Directives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Arg:
    """
    A single named parameter slot accepting one or more types.

    name    doubles as:
              - the param name in ValidatedStatement.params
              - the keyword sentinel when this Arg is wrapped in Keyword
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
    Marks an Arg or Keyword as optional at the statement param level.
    If absent the visitor resolves the Arg.name to None without error.
    Not needed inside Context — statement presence is always implicit there.
    """
    inner: Any


@dataclass(frozen=True)
class Negatable:
    """
    Marks that the inner element may be preceded by '!' in the source.
    Without this wrapper a Negated AST node at this position is an error.
    The resolved ValidatedStatement carries negation as a boolean attribute.
    """
    inner: Any


@dataclass(frozen=True)
class Wildcard:
    """
    When the token value is '*' resolves to None without coercing through
    the inner type. Otherwise the inner Arg type is used normally.
    """
    inner: Any


@dataclass(frozen=True)
class Deprecated:
    """
    Marks a Statement as deprecated.
    The visitor registers a WARNING but does not raise an error.
    Processing continues normally through the inner statement.
    """
    inner: Any


@dataclass(frozen=True)
class Multiple:
    """
    Allows one or more occurrences of the inner Statement within its
    context. Uniqueness is the default assumption — Multiple is the
    explicit exception declared at the context level.

    attr    optional override for the key name used when accumulating
            multiple occurrences into ValidatedStatement.params.
            Defaults to inner.keyword.replace('-', '_').
    """
    inner: Any
    attr:  str | None = None


@dataclass(frozen=True)
class OneOf:
    """
    Tries each option in order and uses the first that matches.

    At the value level (inside Arg.types):
        tries each type descriptor until one coerces successfully.

    At the statement level (inside ListOf):
        matches the current keyword against each StatementDef and
        dispatches to the first that matches.
    """
    options: tuple[Any, ...]

    def __init__(self, *options: Any) -> None:
        object.__setattr__(self, "options", options)


@dataclass(frozen=True)
class ExclusiveOf:
    """
    Exactly one of the given StatementDefs may appear in the enclosing
    Context body. The visitor emits an error if a second one is encountered.
    Used for mutually exclusive alternatives like logging destinations.
    """
    options: tuple[Any, ...]

    def __init__(self, *options: Any) -> None:
        object.__setattr__(self, "options", options)


@dataclass(frozen=True)
class Variadic:
    """
    Consumes all remaining tokens of the inner type into a list.
    Must be the last element in its containing param list.
    Use ListOf for brace-enclosed repetition — Variadic is for
    inline token sequences without surrounding braces.
    """
    inner: Any


@dataclass(frozen=True)
class ListOf:
    """
    Expects a brace-enclosed AST Block node and resolves its contents
    into a homogeneous list. Implicitly allows one or more elements.

    inner   the type descriptor or StatementDef for each element.
            OneOf can be used to allow multiple element shapes.
    """
    inner: Any


@dataclass(frozen=True)
class Context:
    """
    Resolves a sequence of statements into a dict of named params.

    Applies to two AST node types:
      - Conf:  the top-level sequence of statements in a named.conf file.
      - Block: a brace-enclosed sequence of statements nested inside
               another statement, e.g. options { }, zone { }, key { }.

    Use Context when the result should be a structured set of named params.
    Use ListOf when the result should be a homogeneous list.
    """
    statements: tuple[Any, ...]

    def __init__(self, *statements: Any) -> None:
        object.__setattr__(self, "statements", statements)


# ---------------------------------------------------------------------------
# Statement definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StatementDef:
    """
    Defines the shape of one named statement.

    keyword  the first token that identifies this statement.
             Empty string means no keyword — all values are positional.
    params   ordered sequence of Arg / Keyword / Optional / ListOf /
             Context slots describing the statement's value sequence.
    attr     optional override for the key name used when storing this
             statement's result in a parent params dict.
             Defaults to keyword.replace('-', '_').

    Note: node_class is intentionally absent. The mapping from validated
    statements to domain objects is the TransformationVisitor's job.
    """
    keyword: str
    params:  tuple[Any, ...]
    attr:    str | None = None

    def __init__(
        self,
        keyword: str,
        *params: Any,
        attr:    str | None = None,
    ) -> None:
        object.__setattr__(self, "keyword", keyword)
        object.__setattr__(self, "params",  params)
        object.__setattr__(self, "attr",    attr)
