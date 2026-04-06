from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from itertools import groupby
from typing import Any, Callable
import ipaddress
from isc.named.lexer import Token, Word, Number, String
from isc.named.parser import (
    Node, Conf, Statement, Block, Negated,
)
from isc.named.visitor import Visitor


__all__ = [
    "validate",
    "SchemaValidator",
    "SymbolCollector",
    "SymbolTable",
    "ValidationError",
    "Severity",
]


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class Severity(Enum):
    ERROR   = auto()
    WARNING = auto()


@dataclass(frozen=True)
class ValidationError:
    severity: Severity
    message:  str
    line:     int
    col:      int

    def __str__(self) -> str:
        level = "error" if self.severity == Severity.ERROR else "warning"
        return f"{level} at line {self.line}, col {self.col}: {self.message}"


# ---------------------------------------------------------------------------
# Symbol table
# ---------------------------------------------------------------------------

@dataclass
class SymbolTable:
    acls:  set[str] = field(default_factory=set)
    keys:  set[str] = field(default_factory=set)
    views: set[str] = field(default_factory=set)
    zones: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Value constraints
#
# These refine the coarse ArgType with semantic rules.  A constraint is
# checked after the structural type check passes.
# ---------------------------------------------------------------------------

class ArgType(Enum):
    WORD    = auto()
    STRING  = auto()
    NUMBER  = auto()
    ANY     = auto()   # Word | String | Number


# Convenience aliases
WORD   = ArgType.WORD
STRING = ArgType.STRING
NUMBER = ArgType.NUMBER
ANY    = ArgType.ANY


def _token_matches(tok: Token, typ: ArgType) -> bool:
    if typ == ArgType.ANY:    return isinstance(tok, (Word, String, Number))
    if typ == ArgType.WORD:   return isinstance(tok, Word)
    if typ == ArgType.STRING: return isinstance(tok, String)
    if typ == ArgType.NUMBER: return isinstance(tok, Number)
    return False


@dataclass(frozen=True)
class EnumConstraint:
    """Value must be one of the listed strings (case-insensitive)."""
    values: frozenset[str]

    def __init__(self, values: list[str]) -> None:
        object.__setattr__(self, 'values', frozenset(v.lower() for v in values))

    def check(self, tok: Token) -> str | None:
        """Return an error message or None if valid."""
        raw = tok.raw.strip('"').lower()
        if raw not in self.values:
            listed = ", ".join(sorted(self.values))
            return f"expected one of [{listed}], got {tok.raw!r}"
        return None


@dataclass(frozen=True)
class RangeConstraint:
    """Numeric value must be within [minimum, maximum]."""
    minimum: int
    maximum: int

    def check(self, tok: Token) -> str | None:
        if not isinstance(tok, Number):
            return None   # structural check handles wrong type
        if not (self.minimum <= tok.value <= self.maximum):
            return f"value {tok.value} out of range [{self.minimum}, {self.maximum}]"
        return None


@dataclass(frozen=True)
class BoolConstraint:
    """
    Boolean value — by default yes/no, but extensible for options that
    accept additional words like 'explicit', 'auto', 'master-only'.
    """
    true_values:  frozenset[str]
    false_values: frozenset[str]

    def __init__(
        self,
        true_values:  list[str] | None = None,
        false_values: list[str] | None = None,
    ) -> None:
        object.__setattr__(
            self, 'true_values',
            frozenset(v.lower() for v in (true_values  or ["yes"]))
        )
        object.__setattr__(
            self, 'false_values',
            frozenset(v.lower() for v in (false_values or ["no"]))
        )

    def check(self, tok: Token) -> str | None:
        raw = tok.raw.lower()
        valid = self.true_values | self.false_values
        if raw not in valid:
            listed = ", ".join(sorted(valid))
            return f"expected boolean [{listed}], got {tok.raw!r}"
        return None


# Pre-built common constraints
BOOL     = BoolConstraint()
PORT     = RangeConstraint(0, 65535)
BOOLEAN  = BOOL   # alias


# ---------------------------------------------------------------------------
# Schema parts
#
# Four part types — Literal removed, NamedArg covers keyword+value uniformly.
#
# sequence controls matching order:
#   0 (default) — unordered: part may appear anywhere among other seq-0 parts
#   N > 0       — positional: all seq-N parts are matched before seq-(N+1) parts
#
# Parts sharing the same non-zero sequence number form a positional group and
# are matched left-to-right in definition order within that group.
# ---------------------------------------------------------------------------

class Part:
    optional: bool  = False
    sequence: int   = 0     # 0 = unordered


@dataclass(frozen=True)
class Arg(Part):
    """
    A single typed and optionally constrained value token.

        recursion yes;         → Arg(WORD, "boolean", BOOL)
        max-cache-ttl 3600;    → Arg(NUMBER, "seconds", RangeConstraint(0, 2**32-1))
        directory "/var/named";→ Arg(STRING, "path")
        zone "name" [class];   → Arg(STRING, "name", sequence=1),
                                  Arg(WORD, "class", optional=True, sequence=2)
    """
    type:       ArgType
    name:       str
    constraint: EnumConstraint | RangeConstraint | BoolConstraint | None = None
    optional:   bool = False
    sequence:   int  = 0


@dataclass(frozen=True)
class NamedArg(Part):
    """
    A keyword followed by a single typed value.  Replaces the old
    Literal + Arg pair for all keyword-value sub-clauses.

        port 953;       → NamedArg("port",      Arg(NUMBER, "port", PORT))
        perm 0600;      → NamedArg("perm",      Arg(NUMBER, "mode"))
        read-only yes;  → NamedArg("read-only", Arg(WORD, "boolean", BOOL))
        forward first;  → NamedArg("forward",   Arg(WORD, "mode", EnumConstraint(["first","only"])))
    """
    keyword:    str
    arg:        Arg
    optional:   bool = True
    sequence:   int  = 0


@dataclass(frozen=True)
class NamedBlock(Part):
    """
    A keyword followed by a block.

        allow { ... };        → NamedBlock("allow", schema=_ADDRESS_ONLY_BLOCK)
        keys  { ... };        → NamedBlock("keys",  schema=_KEYS_BLOCK, optional=True)
    """
    keyword:      str
    block_schema: BlockSchema | None = None
    optional:     bool               = False
    sequence:     int                = 0


@dataclass(frozen=True)
class BlockPart(Part):
    """
    A bare block (not preceded by a keyword).

        options { ... };  → BlockPart(schema=_OPTIONS_BLOCK)
        acl x { ... };   → ..., BlockPart(schema=_ADDRESS_ONLY_BLOCK)
    """
    block_schema: BlockSchema | None = None
    optional:     bool               = False
    sequence:     int                = 0


@dataclass
class KeywordSchema:
    """
    Describes the full syntactic form of a keyword's statement as an
    ordered sequence of Parts.

    parts are matched in ascending sequence order.  Parts with sequence=0
    are matched last as an unordered optional set.  Parts sharing the same
    non-zero sequence number are matched as a positional group in definition
    order within that group.

    Examples:

        # notify;
        KeywordSchema()

        # recursion yes|no;
        KeywordSchema(parts=[Arg(WORD, "boolean", BOOL)])

        # zone "name" [class] { ... };
        KeywordSchema(parts=[
            Arg(STRING, "name",  sequence=1),
            Arg(WORD,   "class", optional=True, sequence=2),
            BlockPart(schema=_ZONE_BLOCK, sequence=3),
        ])

        # inet addr [port N] allow { } [keys { }] [read-only bool]
        KeywordSchema(parts=[
            Arg(ANY, "address",                             sequence=1),
            NamedArg("port", Arg(NUMBER,"port",PORT),       sequence=2),
            NamedBlock("allow", schema=_ADDRESS_ONLY_BLOCK, sequence=3),
            NamedBlock("keys",  schema=_KEYS_BLOCK, optional=True),   # seq=0
            NamedArg("read-only", Arg(WORD,"boolean",BOOL), optional=True),
        ])

        # unix path perm N owner N group N [keys {}] [read-only bool]
        KeywordSchema(parts=[
            Arg(STRING, "path",                               sequence=1),
            NamedArg("perm",  Arg(NUMBER,"mode"),             sequence=2),
            NamedArg("owner", Arg(NUMBER,"uid"),              sequence=3),
            NamedArg("group", Arg(NUMBER,"gid"),              sequence=4),
            NamedBlock("keys", schema=_KEYS_BLOCK, optional=True),
            NamedArg("read-only", Arg(WORD,"boolean",BOOL), optional=True),
        ])
    """
    parts:      list[Part] = field(default_factory=list)
    repeatable: bool       = False
    deprecated: bool       = False   # emit warning instead of validating


@dataclass
class BlockSchema:
    keywords:              dict[str, KeywordSchema] = field(default_factory=dict)
    allow_address_entries: bool                     = False
    allow_unknown:         bool                     = False


# ---------------------------------------------------------------------------
# Address match element validation — uses ipaddress for correctness
# ---------------------------------------------------------------------------

_PREDEFINED = frozenset({"any", "none", "localhost", "localnets"})


def _is_address_element(value: str) -> bool:
    """
    Return True if value is a syntactically valid address match element:
    a predefined keyword, an IPv4/IPv6 address, or a CIDR prefix.
    Uses the ipaddress module for numeric correctness — 345.345.345.345
    is correctly rejected.
    """
    if value in _PREDEFINED:
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    return False


# ---------------------------------------------------------------------------
# Shared block schemas
# ---------------------------------------------------------------------------

_KEYS_BLOCK = BlockSchema(allow_address_entries=True)

_ADDRESS_ONLY_BLOCK = BlockSchema(
    allow_address_entries=True,
    keywords={
        "key": KeywordSchema(parts=[Arg(ANY, "keyname")]),
    },
)

_LOGGING_CHANNEL_BLOCK = BlockSchema(keywords={
    "file":           KeywordSchema(parts=[Arg(STRING, "filename")]),
    "syslog":         KeywordSchema(parts=[Arg(WORD, "facility", optional=True)]),
    "null":           KeywordSchema(),
    "stderr":         KeywordSchema(),
    "severity":       KeywordSchema(parts=[Arg(WORD, "level",
                          EnumConstraint(["critical","error","warning","notice",
                                          "info","debug","dynamic"]))]),
    "print-time":     KeywordSchema(parts=[Arg(WORD, "boolean", BOOL, optional=True)]),
    "print-severity": KeywordSchema(parts=[Arg(WORD, "boolean", BOOL, optional=True)]),
    "print-category": KeywordSchema(parts=[Arg(WORD, "boolean", BOOL, optional=True)]),
})

_LOGGING_BLOCK = BlockSchema(keywords={
    "channel":  KeywordSchema(
        parts=[
            Arg(WORD, "name",    sequence=1),
            BlockPart(block_schema=_LOGGING_CHANNEL_BLOCK, sequence=2),
        ],
        repeatable=True,
    ),
    "category": KeywordSchema(
        parts=[
            Arg(WORD, "name",    sequence=1),
            BlockPart(block_schema=_ADDRESS_ONLY_BLOCK, sequence=2),
        ],
        repeatable=True,
    ),
})

_ZONE_BLOCK = BlockSchema(allow_unknown=True, keywords={
    "type":           KeywordSchema(parts=[
                          Arg(WORD, "type",
                              EnumConstraint(["primary","secondary","master",
                                             "slave","stub","hint","forward",
                                             "static-stub","redirect","delegation-only"]))
                      ]),
    "file":           KeywordSchema(parts=[Arg(STRING, "filename")]),
    "masters":        KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "allow-update":   KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "allow-query":    KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "allow-transfer": KeywordSchema(parts=[
        NamedArg("port",      Arg(NUMBER, "port",      PORT), optional=True),
        NamedArg("transport", Arg(WORD,   "transport"),       optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK),
    ]),
    "notify":         KeywordSchema(parts=[
                          Arg(WORD, "boolean",
                              EnumConstraint(["yes","no","explicit","master-only","primary-only"]))
                      ]),
    "also-notify":    KeywordSchema(parts=[
        NamedArg("port", Arg(NUMBER, "port", PORT), optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK, optional=True),
    ]),
    "forward":        KeywordSchema(parts=[
                          Arg(WORD, "mode", EnumConstraint(["first","only"]))
                      ]),
    "forwarders":     KeywordSchema(parts=[
        NamedArg("port", Arg(NUMBER, "port", PORT), optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK),
    ]),
})

_OPTIONS_BLOCK = BlockSchema(allow_unknown=True, keywords={
    "directory":         KeywordSchema(parts=[Arg(STRING, "path")]),
    "recursion":         KeywordSchema(parts=[Arg(WORD, "boolean", BOOL)]),
    "listen-on":         KeywordSchema(parts=[
        NamedArg("port", Arg(NUMBER, "port", PORT), optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK, optional=True),
    ]),
    "listen-on-v6":      KeywordSchema(parts=[
        NamedArg("port", Arg(NUMBER, "port", PORT), optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK, optional=True),
    ]),
    "forwarders":        KeywordSchema(parts=[
        NamedArg("port", Arg(NUMBER, "port", PORT), optional=True),
        BlockPart(block_schema=_ADDRESS_ONLY_BLOCK),
    ]),
    "forward":           KeywordSchema(parts=[
                             Arg(WORD, "mode", EnumConstraint(["first","only"]))
                         ]),
    "allow-query":       KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "allow-recursion":   KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "allow-transfer":    KeywordSchema(parts=[BlockPart(block_schema=_ADDRESS_ONLY_BLOCK)]),
    "max-cache-ttl":     KeywordSchema(parts=[Arg(NUMBER, "seconds", RangeConstraint(0, 2**32-1))]),
    "max-ncache-ttl":    KeywordSchema(parts=[Arg(NUMBER, "seconds", RangeConstraint(0, 604800))]),
    "notify":            KeywordSchema(parts=[
                             Arg(WORD, "boolean",
                                 EnumConstraint(["yes","no","explicit","master-only","primary-only"]))
                         ]),
    "dnssec-validation": KeywordSchema(parts=[
                             Arg(WORD, "mode", EnumConstraint(["yes","no","auto"]))
                         ]),
    "version":           KeywordSchema(parts=[Arg(STRING, "string")]),
    "server-id":         KeywordSchema(parts=[Arg(STRING, "string")]),
    "querylog":          KeywordSchema(parts=[Arg(WORD, "boolean", BOOL)]),
})

_CONTROLS_BLOCK = BlockSchema(keywords={
    "inet": KeywordSchema(
        parts=[
            Arg(ANY, "address",                                    sequence=1),
            NamedArg("port", Arg(NUMBER, "port", PORT),            sequence=2),
            NamedBlock("allow", block_schema=_ADDRESS_ONLY_BLOCK,  sequence=3),
            NamedBlock("keys",  block_schema=_KEYS_BLOCK, optional=True),
            NamedArg("read-only", Arg(WORD, "boolean", BOOL), optional=True),
        ],
        repeatable=True,
    ),
    "unix": KeywordSchema(
        parts=[
            Arg(STRING, "path",                                              sequence=1),
            NamedArg("perm",  Arg(NUMBER, "mode"), optional=False,           sequence=2),
            NamedArg("owner", Arg(NUMBER, "uid"),  optional=False,           sequence=3),
            NamedArg("group", Arg(NUMBER, "gid"),  optional=False,           sequence=4),
            NamedBlock("keys",    block_schema=_KEYS_BLOCK, optional=True),
            NamedArg("read-only", Arg(WORD, "boolean", BOOL), optional=True),
        ],
        repeatable=True,
    ),
})

_KEY_BLOCK = BlockSchema(keywords={
    "algorithm": KeywordSchema(parts=[Arg(ANY, "name")]),
    "secret":    KeywordSchema(parts=[Arg(ANY, "key")]),
})

_TOP_LEVEL = BlockSchema(keywords={
    "options":             KeywordSchema(parts=[BlockPart(block_schema=_OPTIONS_BLOCK)]),
    "logging":             KeywordSchema(parts=[BlockPart(block_schema=_LOGGING_BLOCK)]),
    "controls":            KeywordSchema(parts=[BlockPart(block_schema=_CONTROLS_BLOCK)]),
    "acl":                 KeywordSchema(parts=[
                               Arg(WORD, "name",      sequence=1),
                               BlockPart(block_schema=_ADDRESS_ONLY_BLOCK, sequence=2),
                           ], repeatable=True),
    "zone":                KeywordSchema(parts=[
                               Arg(STRING, "name",    sequence=1),
                               Arg(WORD,   "class",   optional=True, sequence=2),
                               BlockPart(block_schema=_ZONE_BLOCK, sequence=3),
                           ], repeatable=True),
    "key":                 KeywordSchema(parts=[
                               Arg(ANY, "name",       sequence=1),
                               BlockPart(block_schema=_KEY_BLOCK, sequence=2),
                           ], repeatable=True),
    "view":                KeywordSchema(parts=[
                               Arg(STRING, "name",    sequence=1),
                               Arg(WORD,   "class",   optional=True, sequence=2),
                               BlockPart(block_schema=BlockSchema(allow_unknown=True), sequence=3),
                           ], repeatable=True),
    "server":              KeywordSchema(parts=[
                               Arg(WORD, "address",   sequence=1),
                               BlockPart(block_schema=BlockSchema(allow_unknown=True), sequence=2),
                           ], repeatable=True),
    "include":             KeywordSchema(parts=[Arg(STRING, "filename")]),
    "trusted-keys":        KeywordSchema(parts=[BlockPart(block_schema=BlockSchema(allow_unknown=True))]),
    "managed-keys":        KeywordSchema(parts=[BlockPart(block_schema=BlockSchema(allow_unknown=True))]),
    "statistics-channels": KeywordSchema(parts=[BlockPart(block_schema=BlockSchema(allow_unknown=True))]),
})


# ---------------------------------------------------------------------------
# Validation context
# ---------------------------------------------------------------------------

@dataclass
class ValidationContext:
    schema:       BlockSchema
    symbol_table: SymbolTable
    path:         list[str]      = field(default_factory=list)
    seen:         dict[str, int] = field(default_factory=dict)

    def child(self, keyword: str, schema: BlockSchema) -> ValidationContext:
        return ValidationContext(
            schema=schema,
            symbol_table=self.symbol_table,
            path=self.path + [keyword],
        )

    def location(self) -> str:
        return " > ".join(self.path) if self.path else "top level"


# ---------------------------------------------------------------------------
# Sequence matcher
# ---------------------------------------------------------------------------

class _SequenceMatcher:
    """
    Matches a statement's token+block values against an ordered Part list.

    Parts are grouped by their sequence number.  Positional groups (seq > 0)
    are processed in ascending order, left-to-right within the group.
    Unordered parts (seq == 0) are processed last — each is looked up
    anywhere in the remaining values rather than consumed positionally.
    """

    def __init__(
        self,
        node:    Statement,
        values:  list[Token | Block],
        parts:   list[Part],
        errors:  list[ValidationError],
        ctx:     ValidationContext,
        recurse: Any,
    ) -> None:
        self._node    = node
        self._values  = list(values)
        self._parts   = parts
        self._errors  = errors
        self._ctx     = ctx
        self._recurse = recurse
        self._keyword = self._kw(node)

    @staticmethod
    def _kw(node: Statement) -> str:
        v = node.values[0] if node.values else None
        return v.value if isinstance(v, Word) else ""  # type: ignore[union-attr]

    def _error(self, msg: str) -> None:
        self._errors.append(ValidationError(
            severity=Severity.ERROR,
            message=f"[{self._ctx.location()}] {msg}",
            line=self._node.span.line,
            col=self._node.span.col,
        ))

    def _warning(self, msg: str) -> None:
        self._errors.append(ValidationError(
            severity=Severity.WARNING,
            message=f"[{self._ctx.location()}] {msg}",
            line=self._node.span.line,
            col=self._node.span.col,
        ))

    def match(self) -> None:
        # Separate positional (seq > 0) from unordered (seq == 0)
        positional = [p for p in self._parts if p.sequence > 0]
        unordered  = [p for p in self._parts if p.sequence == 0]

        # Process positional groups in sequence order
        sorted_pos = sorted(positional, key=lambda p: p.sequence)
        for _, group in groupby(sorted_pos, key=lambda p: p.sequence):
            for part in group:
                self._consume_positional(part)

        # Process unordered parts — scan remaining values for each
        for part in unordered:
            self._consume_unordered(part)

        # Anything left is unexpected
        if self._values:
            extra = " ".join(
                v.raw if isinstance(v, Token) else "{...}"  # type: ignore[union-attr]
                for v in self._values
            )
            self._error(f"{self._keyword!r} has unexpected trailing value(s): {extra}")

    # ------------------------------------------------------------------
    # Positional matching — consumes from the front of self._values
    # ------------------------------------------------------------------

    def _consume_positional(self, part: Part) -> None:
        if isinstance(part, Arg):
            self._pos_arg(part)
        elif isinstance(part, NamedArg):
            self._pos_named_arg(part)
        elif isinstance(part, NamedBlock):
            self._pos_named_block(part)
        elif isinstance(part, BlockPart):
            self._pos_block(part)

    def _peek(self) -> Token | Block | None:
        return self._values[0] if self._values else None

    def _advance(self) -> Token | Block:
        return self._values.pop(0)

    def _peek_is_word(self, word: str) -> bool:
        v = self._peek()
        return isinstance(v, Word) and v.value == word

    def _peek_is_block(self) -> bool:
        return isinstance(self._peek(), Block)

    def _peek_is_token(self, typ: ArgType) -> bool:
        v = self._peek()
        return isinstance(v, Token) and _token_matches(v, typ)

    def _check_constraint(
        self,
        tok:        Token,
        constraint: EnumConstraint | RangeConstraint | BoolConstraint | None,
        label:      str,
    ) -> None:
        if constraint is None:
            return
        msg = constraint.check(tok)
        if msg:
            self._error(f"{self._keyword!r} {label}: {msg}")

    def _pos_arg(self, part: Arg) -> None:
        v = self._peek()
        if v is None or isinstance(v, Block):
            if not part.optional:
                self._error(f"{self._keyword!r} missing required argument {part.name!r}")
            return
        if not _token_matches(v, part.type):
            if part.optional:
                return
            self._error(
                f"{self._keyword!r} argument {part.name!r} should be a "
                f"{part.type.name.lower()}, got {type(v).__name__} {v.raw!r}"  # type: ignore[union-attr]
            )
            self._advance()
            return
        tok = self._advance()
        assert isinstance(tok, Token)
        self._check_constraint(tok, part.constraint, f"argument {part.name!r}")

    def _pos_named_arg(self, part: NamedArg) -> None:
        if not self._peek_is_word(part.keyword):
            if not part.optional:
                self._error(
                    f"{self._keyword!r} missing required sub-keyword {part.keyword!r}"
                )
            return
        self._advance()   # consume keyword
        v = self._peek()
        if v is None or isinstance(v, Block):
            self._error(f"{self._keyword!r} {part.keyword!r} requires a value")
            return
        if not _token_matches(v, part.arg.type):
            self._error(
                f"{self._keyword!r} {part.keyword!r} value should be a "
                f"{part.arg.type.name.lower()}, got {type(v).__name__} {v.raw!r}"  # type: ignore[union-attr]
            )
            self._advance()
            return
        tok = self._advance()
        assert isinstance(tok, Token)
        self._check_constraint(tok, part.arg.constraint, f"'{part.keyword}' value")

    def _pos_named_block(self, part: NamedBlock) -> None:
        if not self._peek_is_word(part.keyword):
            if not part.optional:
                self._error(
                    f"{self._keyword!r} missing required sub-keyword {part.keyword!r} {{ }}"
                )
            return
        self._advance()
        if not self._peek_is_block():
            self._error(
                f"{self._keyword!r} {part.keyword!r} must be followed by a block {{ }}"
            )
            return
        blk = self._advance()
        assert isinstance(blk, Block)
        if part.block_schema is not None:
            self._recurse(blk, self._ctx.child(part.keyword, part.block_schema))

    def _pos_block(self, part: BlockPart) -> None:
        if not self._peek_is_block():
            if not part.optional:
                self._error(f"{self._keyword!r} requires a block {{ }}")
            return
        blk = self._advance()
        assert isinstance(blk, Block)
        if part.block_schema is not None:
            self._recurse(blk, self._ctx.child(self._keyword, part.block_schema))

    # ------------------------------------------------------------------
    # Unordered matching — scans self._values for the part anywhere
    # ------------------------------------------------------------------

    def _consume_unordered(self, part: Part) -> None:
        if isinstance(part, NamedArg):
            self._unordered_named_arg(part)
        elif isinstance(part, NamedBlock):
            self._unordered_named_block(part)
        elif isinstance(part, BlockPart):
            self._unordered_block(part)
        elif isinstance(part, Arg):
            # Unordered bare Arg — treat positionally from remaining values
            self._pos_arg(part)

    def _find_word(self, keyword: str) -> int | None:
        """Return index of the first Word(keyword) in remaining values, or None."""
        for i, v in enumerate(self._values):
            if isinstance(v, Word) and v.value == keyword:
                return i
        return None

    def _find_block(self) -> int | None:
        """Return index of the first Block in remaining values, or None."""
        for i, v in enumerate(self._values):
            if isinstance(v, Block):
                return i
        return None

    def _unordered_named_arg(self, part: NamedArg) -> None:
        idx = self._find_word(part.keyword)
        if idx is None:
            if not part.optional:
                self._error(
                    f"{self._keyword!r} missing required sub-keyword {part.keyword!r}"
                )
            return
        self._values.pop(idx)   # consume keyword
        # The value must immediately follow the keyword
        if idx >= len(self._values):
            self._error(f"{self._keyword!r} {part.keyword!r} requires a value")
            return
        v = self._values[idx]
        if isinstance(v, Block) or not _token_matches(v, part.arg.type):
            self._error(
                f"{self._keyword!r} {part.keyword!r} value should be a "
                f"{part.arg.type.name.lower()}"
            )
            self._values.pop(idx)
            return
        tok = self._values.pop(idx)
        assert isinstance(tok, Token)
        self._check_constraint(tok, part.arg.constraint, f"'{part.keyword}' value")

    def _unordered_named_block(self, part: NamedBlock) -> None:
        idx = self._find_word(part.keyword)
        if idx is None:
            if not part.optional:
                self._error(
                    f"{self._keyword!r} missing required sub-keyword {part.keyword!r} {{ }}"
                )
            return
        self._values.pop(idx)
        if idx >= len(self._values) or not isinstance(self._values[idx], Block):
            self._error(
                f"{self._keyword!r} {part.keyword!r} must be followed by a block {{ }}"
            )
            return
        blk = self._values.pop(idx)
        assert isinstance(blk, Block)
        if part.block_schema is not None:
            self._recurse(blk, self._ctx.child(part.keyword, part.block_schema))

    def _unordered_block(self, part: BlockPart) -> None:
        idx = self._find_block()
        if idx is None:
            if not part.optional:
                self._error(f"{self._keyword!r} requires a block {{ }}")
            return
        blk = self._values.pop(idx)
        assert isinstance(blk, Block)
        if part.block_schema is not None:
            self._recurse(blk, self._ctx.child(self._keyword, part.block_schema))


# ---------------------------------------------------------------------------
# Symbol collector (pass 1)
# ---------------------------------------------------------------------------

class SymbolCollector(Visitor):
    """Collects all top-level name definitions into a SymbolTable."""

    def __init__(self) -> None:
        self._table = SymbolTable()

    def visit_conf(self, node: Conf) -> SymbolTable:
        for child in node.body:
            child.accept(self)
        return self._table

    def visit_statement(self, node: Statement) -> None:
        if not node.values or not isinstance(node.values[0], Word):
            return
        keyword = node.values[0].value
        if len(node.values) < 2:
            return
        name_tok = node.values[1]
        if isinstance(name_tok, Block):
            return
        name = (
            name_tok.value.strip('"')   # type: ignore[union-attr]
            if isinstance(name_tok, (Word, String))
            else name_tok.raw
        )
        if keyword == "acl":    self._table.acls.add(name)
        elif keyword == "key":  self._table.keys.add(name)
        elif keyword == "view": self._table.views.add(name)
        elif keyword == "zone": self._table.zones.add(name)

    def visit_block(self, node: Block) -> None:
        pass

    def visit_negated(self, node: Negated) -> None:
        pass


# ---------------------------------------------------------------------------
# Schema validator (pass 2)
# ---------------------------------------------------------------------------

class SchemaValidator(Visitor):
    """
    Context-aware schema validator.

    visit_conf creates the root ValidationContext and iterates top-level
    nodes.  visit_statement validates each statement against the context
    schema using a _SequenceMatcher that respects sequence-based ordering.
    Context is stored as instance state so visit_statement always has it.
    """

    def __init__(self, symbol_table: SymbolTable | None = None) -> None:
        self._errors: list[ValidationError] = []
        self._table   = symbol_table or SymbolTable()
        self._ctx: ValidationContext | None = None

    def _error(self, node: Node, msg: str) -> None:
        assert self._ctx is not None
        self._errors.append(ValidationError(
            severity=Severity.ERROR,
            message=f"[{self._ctx.location()}] {msg}",
            line=node.span.line,
            col=node.span.col,
        ))

    def _warning(self, node: Node, msg: str) -> None:
        assert self._ctx is not None
        self._errors.append(ValidationError(
            severity=Severity.WARNING,
            message=f"[{self._ctx.location()}] {msg}",
            line=node.span.line,
            col=node.span.col,
        ))

    # ------------------------------------------------------------------
    # Visitor entry points
    # ------------------------------------------------------------------

    def visit_conf(self, node: Conf) -> list[ValidationError]:
        ctx = ValidationContext(schema=_TOP_LEVEL, symbol_table=self._table)
        for child in node.body:
            self._validate_in_context(child, ctx)
        return sorted(self._errors, key=lambda e: (e.line, e.col))

    def visit_statement(self, node: Statement) -> None:
        assert self._ctx is not None
        ctx = self._ctx

        keyword = self._keyword_of(node)

        # Address-only block entry (no keyword)
        if keyword is None:
            if ctx.schema.allow_address_entries:
                self._validate_address_entry(node, ctx)
            else:
                self._error(node, "Statement has no keyword")
            return

        # key reference inside address block
        if keyword == "key" and ctx.schema.allow_address_entries:
            self._validate_key_reference(node, ctx)
            return

        kschema = ctx.schema.keywords.get(keyword)

        if kschema is None:
            if ctx.schema.allow_address_entries and self._is_acl_reference(keyword):
                return
            if ctx.schema.allow_address_entries:
                self._validate_address_entry(node, ctx)
                return
            if not ctx.schema.allow_unknown:
                self._warning(node, f"Unknown keyword {keyword!r}")
            return

        if kschema.deprecated:
            self._warning(node, f"Keyword {keyword!r} is deprecated")
            return

        # Duplicate check
        count = ctx.seen.get(keyword, 0) + 1
        ctx.seen[keyword] = count
        if count > 1 and not kschema.repeatable:
            self._error(node, f"Duplicate keyword {keyword!r}")

        # Match parts using sequence-aware matcher
        values_after_keyword: list[Token | Block] = list(node.values[1:])
        matcher = _SequenceMatcher(
            node, values_after_keyword, kschema.parts,
            self._errors, ctx, self._recurse_into_block,
        )
        matcher.match()

    def visit_block(self, node: Block) -> None:
        pass

    def visit_negated(self, node: Negated) -> None:
        assert self._ctx is not None
        ctx = self._ctx
        if not ctx.schema.allow_address_entries:
            self._error(node, "Negated entry not valid in this context")
            return
        self._validate_in_context(node.inner, ctx)

    # ------------------------------------------------------------------
    # Context-aware traversal
    # ------------------------------------------------------------------

    def _validate_in_context(
        self,
        node: Statement | Block | Negated,
        ctx:  ValidationContext,
    ) -> None:
        self._ctx = ctx
        if isinstance(node, (Statement, Negated)):
            node.accept(self)
        elif isinstance(node, Block):
            self._recurse_into_block(node, ctx)

    def _recurse_into_block(self, block: Block, ctx: ValidationContext) -> None:
        for child in block.body:
            self._validate_in_context(child, ctx)

    # ------------------------------------------------------------------
    # Address match element validation
    # ------------------------------------------------------------------

    def _validate_address_entry(
        self, node: Statement, ctx: ValidationContext
    ) -> None:
        if not node.values:
            self._error(node, "Empty address match entry")
            return
        tok = node.values[0]
        if isinstance(tok, String):
            return   # quoted string in keys block
        if not isinstance(tok, Word):
            self._error(
                node,
                f"Address match entry should be a word, "
                f"got {type(tok).__name__} {tok.raw!r}"  # type: ignore[union-attr]
            )
            return
        value = tok.value
        if _is_address_element(value):
            return
        if self._is_acl_reference(value):
            return
        self._warning(
            node,
            f"Unrecognised address match element {value!r} "
            f"(not a valid address, CIDR, predefined keyword, or known ACL name)"
        )

    def _validate_key_reference(
        self, node: Statement, ctx: ValidationContext
    ) -> None:
        if len(node.values) < 2:
            self._error(node, "'key' requires a name argument")
            return
        name_tok = node.values[1]
        name = (
            name_tok.value.strip('"')  # type: ignore[union-attr]
            if isinstance(name_tok, (Word, String))
            else name_tok.raw
        )
        if name not in self._table.keys:
            self._warning(node, f"Key {name!r} referenced but not defined")

    def _is_acl_reference(self, name: str) -> bool:
        return name in self._table.acls

    @staticmethod
    def _keyword_of(node: Statement) -> str | None:
        if node.values and isinstance(node.values[0], Word):
            return node.values[0].value
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(text: str) -> list[ValidationError]:
    """
    Parse and validate a named.conf string.

    Pass 1 — SymbolCollector: build a symbol table of defined names.
    Pass 2 — SchemaValidator: validate each statement against the schema,
             using sequence-aware part matching and the symbol table for
             reference resolution.
    """
    from isc.named.parser import parse
    tree  = parse(text)
    table = tree.accept(SymbolCollector())
    return tree.accept(SchemaValidator(symbol_table=table))
