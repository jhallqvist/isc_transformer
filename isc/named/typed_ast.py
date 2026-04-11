"""
isc.named.typed_ast
~~~~~~~~~~~~~~~~~~~
The Typed AST — the output of the SemanticVisitor.

Design principles
-----------------
  - Grammar-shaped, not domain-shaped. These nodes reflect the structure
    of named.conf as a language, not the structure of DNS configuration.
  - Values are coerced to strong Python types at this layer. The
    TransformationVisitor receives clean Python objects, not raw strings.
  - Reference types (AclRef, KeyRef etc) are named objects, not plain
    strings, so the TransformationVisitor can pattern-match on them and
    knows which require cross-reference resolution.
  - ValidatedStatement is generic — no ZoneStatement or OptionsStatement
    here. That specialisation happens in the TransformationVisitor.

Typed leaf values
-----------------
These are grammar-level facts. Every downstream consumer benefits from
receiving them pre-coerced regardless of what domain model it targets:

  ipaddress.IPv4Address / IPv6Address   — coerced IP addresses
  ipaddress.IPv4Network / IPv6Network   — coerced CIDR prefixes
  int                                   — port, integer, duration (seconds)
  bool                                  — ISC boolean
  str                                   — enum value, string, filename
  TsigAlgorithmValue                    — (base, truncation) named tuple
  AddressMatchElement                   — recursive address-match structure
  AclRef / KeyRef / TlsRef / ViewRef   — pending references (named, not str)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Union

__all__ = [
    # Typed leaf values
    "TsigAlgorithmValue",
    "AddressMatchElement",
    # Reference types
    "AclRef",
    "KeyRef",
    "TlsRef",
    "ViewRef",
    # Validated AST nodes
    "ValidatedParam",
    "ValidatedStatement",
    "ValidatedConf",
]


# ---------------------------------------------------------------------------
# Typed leaf values
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TsigAlgorithmValue:
    """
    A coerced TSIG algorithm name with optional truncation length in bits.
    base:       one of the recognised hmac-* or gss-tsig algorithm names
    truncation: bit-length override, or None for the default output length
    """
    base:       str
    truncation: int | None = None

    def __str__(self) -> str:
        if self.truncation is not None:
            return f"{self.base}-{self.truncation}"
        return self.base


@dataclass(frozen=True)
class AclRef:
    """A pending reference to a named ACL. Resolved by TransformationVisitor."""
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class KeyRef:
    """A pending reference to a named key. Resolved by TransformationVisitor."""
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class TlsRef:
    """A pending reference to a named TLS context. Resolved by TransformationVisitor."""
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ViewRef:
    """A pending reference to a named view. Resolved by TransformationVisitor."""
    name: str

    def __str__(self) -> str:
        return self.name


# Coerced value union — every value in ValidatedParam.value is one of these
CoercedValue = Union[
    str, int, bool, float,
    ipaddress.IPv4Address, ipaddress.IPv6Address,
    ipaddress.IPv4Network, ipaddress.IPv6Network,
    TsigAlgorithmValue,
    AclRef, KeyRef, TlsRef, ViewRef,
    "AddressMatchElement",
    list,
    None,
]


@dataclass
class AddressMatchElement:
    """
    One element in an address-match list.

    Exactly one of the value union members is populated:
      IPv4Address / IPv6Address  — a host address
      IPv4Network / IPv6Network  — a CIDR prefix
      str                        — a built-in name (any, none, localhost…)
      AclRef                     — a reference to a named ACL
      KeyRef                     — a key reference (key "name")
      list[AddressMatchElement]  — a nested address-match block

    negated is True when the element was preceded by '!'.
    """
    negated: bool = False
    value: Union[
        ipaddress.IPv4Address,
        ipaddress.IPv6Address,
        ipaddress.IPv4Network,
        ipaddress.IPv6Network,
        str,
        AclRef,
        KeyRef,
        list["AddressMatchElement"],
        None,
    ] = None

    @property
    def kind(self) -> str:
        if isinstance(self.value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return "address"
        if isinstance(self.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return "network"
        if isinstance(self.value, AclRef):
            return "acl_ref"
        if isinstance(self.value, KeyRef):
            return "key_ref"
        if isinstance(self.value, list):
            return "nested"
        return "builtin"

    def __repr__(self) -> str:
        neg = "!" if self.negated else ""
        return f"{neg}{self.value}"


# ---------------------------------------------------------------------------
# Validated AST nodes
# ---------------------------------------------------------------------------

@dataclass
class ValidatedParam:
    """
    One validated, coerced parameter from a statement.

    name      the Arg.name from the schema — used by TransformationVisitor
              to look up values by name
    value     the coerced Python value
    type_name the DSL type class name e.g. "IpAddressType", "BooleanType"
    raw       the original parser token or node, for span / error reporting
    """
    name:      str
    value:     CoercedValue
    type_name: str
    raw:       Any = field(default=None, repr=False)

    def __repr__(self) -> str:
        return f"ValidatedParam({self.name}={self.value!r})"


@dataclass
class ValidatedStatement:
    """
    A validated statement produced by the SemanticVisitor.

    keyword   the first token value that identified this statement
    params    list of ValidatedParam in schema order
    body      validated children from a block body (if any)
    negated   True if this statement was wrapped in a Negated AST node
    raw       the original parser Statement node

    Lookup helpers
    --------------
    Use param(name) or param_value(name) to retrieve params by name
    rather than indexing into the list directly.
    """
    keyword:  str
    params:   list[ValidatedParam] = field(default_factory=list)
    body:     list["ValidatedStatement"] = field(default_factory=list)
    negated:  bool = False
    raw:      Any  = field(default=None, repr=False)

    def param(self, name: str) -> ValidatedParam | None:
        """Return the first ValidatedParam with the given name, or None."""
        for p in self.params:
            if p.name == name:
                return p
        return None

    def param_value(self, name: str, default: Any = None) -> Any:
        """Return the coerced value of the named param, or default."""
        p = self.param(name)
        return p.value if p is not None else default

    def body_by_keyword(self, keyword: str) -> list["ValidatedStatement"]:
        """Return all body statements with the given keyword."""
        return [s for s in self.body if s.keyword == keyword]

    def body_first(self, keyword: str) -> "ValidatedStatement | None":
        """Return the first body statement with the given keyword, or None."""
        matches = self.body_by_keyword(keyword)
        return matches[0] if matches else None

    def __repr__(self) -> str:
        params_r = ", ".join(repr(p) for p in self.params)
        body_r   = f", body=[{len(self.body)}]" if self.body else ""
        return f"ValidatedStatement({self.keyword!r}, [{params_r}]{body_r})"


@dataclass
class ValidatedConf:
    """
    Root validated node — the output of SemanticVisitor.visit(conf).

    body      top-level validated statements in source order
    errors    validation errors collected during the walk

    Lookup helpers mirror ValidatedStatement for convenience.
    """
    body:   list[ValidatedStatement] = field(default_factory=list)

    def statements_by_keyword(self, keyword: str) -> list[ValidatedStatement]:
        return [s for s in self.body if s.keyword == keyword]

    def first(self, keyword: str) -> ValidatedStatement | None:
        matches = self.statements_by_keyword(keyword)
        return matches[0] if matches else None

    def __repr__(self) -> str:
        return f"ValidatedConf([{len(self.body)} statements])"
