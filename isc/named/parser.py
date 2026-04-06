from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from isc.named.lexer import (
    lex,
    Token, Word, Number, String, Bang, Comment,
    LeftBrace, RightBrace, Semicolon, Eof,
    Span, LexerError,
)

if TYPE_CHECKING:
    from isc.named.visitor import Visitor

__all__ = [
    "parse",
    "Node", "Conf", "Statement", "Block", "Negated",
    "ParseError",
]


# ---------------------------------------------------------------------------
# AST
#
# Three node types map directly to the three structural constructs in
# named.conf.  Token objects from the lexer are carried as-is into
# Statement.values — no semantic classification is performed here.
#
# The grammar is LL(1): one consumed token always determines the node type.
#
#   conf       := node*  EOF
#   node       := block | negated | statement
#   block      := "{"  node*  "}"
#   negated    := "!"  node
#   statement  := value*  ";"
#   value      := WORD | NUMBER | STRING | block
#
# Each node implements accept(visitor) for the visitor pattern.  The
# TYPE_CHECKING guard above keeps the import from isc.named.visitor
# at type-check time only, avoiding a circular runtime import.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Node:
    """Base class for all AST nodes."""
    span: Span

    def accept(self, visitor: Visitor) -> Any:
        raise NotImplementedError


@dataclass(frozen=True)
class Block(Node):
    """
    A brace-enclosed body.  Recognised by a leading '{' token.

        { type master; file "/etc/named/example.com"; }

    Appears inside Statement.values, or as the inner of a Negated node.
    """
    body: tuple[Statement | Negated, ...]

    def accept(self, visitor: Visitor) -> Any:
        return visitor.visit_block(self)

    def __repr__(self) -> str:
        body = ", ".join(repr(s) for s in self.body)
        return f"Block([{body}])"


@dataclass(frozen=True)
class Statement(Node):
    """
    A sequence of value tokens and zero or more Blocks, terminated by ';'.
    Recognised by a leading WORD, NUMBER, or STRING token.
    No keyword/value distinction is made — that is left to the semantic layer.

        recursion yes;
            → values = (Word('recursion'), Word('yes'))

        zone "example.com" IN { type master; };
            → values = (Word('zone'), String('example.com'), Word('IN'),
                        Block([...]))

        also-notify { 192.168.1.1; } port 5353;
            → values = (Word('also-notify'), Block([...]), Word('port'),
                        Number(5353))
    """
    values: tuple[Token | Block, ...]

    @property
    def keyword(self):
        first_token = self.values[0]
        if isinstance(first_token, Word):
            return first_token.value
        return None

    def accept(self, visitor: Visitor) -> Any:
        return visitor.visit_statement(self)

    def __repr__(self) -> str:
        vals = ", ".join(repr(v) for v in self.values)
        return f"Statement([{vals}])"


@dataclass(frozen=True)
class Negated(Node):
    """
    A negation prefix applied to any node.  Recognised by a leading '!' token.

        !192.168.1.0/24;    → Negated(Statement([Word('192.168.1.0/24')]))
        !{ 10.0.0.0/8; };  → Negated(Block([...]))
    """
    inner: Statement | Block

    def accept(self, visitor: Visitor) -> Any:
        return visitor.visit_negated(self)

    def __repr__(self) -> str:
        return f"Negated({self.inner!r})"


@dataclass(frozen=True)
class Conf(Node):
    """Root node of a parsed named.conf file."""
    body: tuple[Statement | Negated, ...]

    def accept(self, visitor: Visitor) -> Any:
        return visitor.visit_conf(self)

    def __repr__(self) -> str:
        stmts = "\n  ".join(repr(s) for s in self.body)
        return f"Conf([\n  {stmts}\n])"


# ---------------------------------------------------------------------------
# ParseError
# ---------------------------------------------------------------------------

class ParseError(ValueError):
    """
    Raised when the token stream does not match the expected grammar.
    Carries the Span of the offending token.
    """
    def __init__(self, message: str, span: Span) -> None:
        super().__init__(message)
        self.span = span

    def __str__(self) -> str:
        return (f"ParseError at line {self.span.line}, col {self.span.col}: "
                f"{super().__str__()}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Parser:
    """
    Recursive-descent parser for ISC named.conf.

    Strips comments and Eof on construction.  Each parse method receives
    the already-consumed token that identified it, advances through its
    body, and returns a fully constructed AST node.

    Node recognition from a single consumed token (LL(1)):

        LeftBrace              →  _parse_block      →  Block
        Bang                   →  _parse_negated    →  Negated
        Word | String | Number →  _parse_statement  →  Statement
    """

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens: list[Token] = [
            t for t in tokens if not isinstance(t, (Comment, Eof))
        ]
        self._pos: int = 0

    def _advance(self) -> Token:
        """Consume and return the current token.  Raises IndexError at EOF."""
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _parse_node(self, tok: Token) -> Statement | Block | Negated:
        """
        Dispatch to the correct parse method based on the consumed token.

            LeftBrace              →  Block
            Bang                   →  Negated
            Word | String | Number →  Statement

        Raises ParseError for any token that cannot start a node.
        """
        if isinstance(tok, LeftBrace):
            return self._parse_block(tok)
        if isinstance(tok, Bang):
            return self._parse_negated(tok)
        if isinstance(tok, (Word, String, Number)):
            return self._parse_statement(tok)
        raise ParseError(
            f"Unexpected {type(tok).__name__} {tok.raw!r} — "
            f"expected '{{', '!' or a value token",
            tok.span,
        )

    def _parse_block(self, open_brace: Token) -> Block:
        """
        Parse a brace-enclosed body.

        The opening '{' has already been consumed and is passed in as
        open_brace for span construction.  Advances until RightBrace is
        consumed by the while condition.

        Raises ParseError if end of input is reached before '}'.
        """
        body: list[Statement | Block | Negated] = []
        try:
            tok = self._advance()
            while not isinstance(tok, RightBrace):
                node = self._parse_node(tok)
                body.append(node)
                # A Block at body level is always followed by ';' — consume it.
                if isinstance(node, Block):
                    tok = self._advance()
                    if not isinstance(tok, Semicolon):
                        raise ParseError(
                            f"Expected ';' after block, "
                            f"got {type(tok).__name__} {tok.raw!r}",
                            tok.span,
                        )
                tok = self._advance()
        except IndexError:
            raise ParseError(
                "Unexpected end of input inside block", open_brace.span)

        # tok is now the RightBrace that ended the loop
        span = Span(
            start=open_brace.span.start,
            end=tok.span.end,
            line=open_brace.span.line,
            col=open_brace.span.col,
        )
        return Block(span=span, body=tuple(body))  # type: ignore[arg-type]

    def _parse_statement(self, first: Token) -> Statement:
        """
        Parse one statement.

        The first token has already been consumed and is passed in as first.
        Advances until Semicolon is consumed by the while condition.

        A LeftBrace mid-statement produces a Block appended to values —
        blocks may appear anywhere in the value sequence:

            also-notify { 192.168.1.1; } port 5353;
            → values = (Word, Block, Word, Number)

        Raises ParseError on RightBrace, end of input, or Bang inside
        a statement.
        """
        values: list[Token | Block] = []
        tok = first
        try:
            while not isinstance(tok, Semicolon):
                if isinstance(tok, RightBrace):
                    raise ParseError(
                        "Unexpected '}' inside statement — "
                        "end of block must be preceeded by a start of block",
                        tok.span
                    )
                if isinstance(tok, Bang):
                    raise ParseError(
                        "Unexpected '!' inside statement — "
                        "negation must appear before a statement",
                        tok.span
                    )
                if isinstance(tok, LeftBrace):
                    values.append(self._parse_block(tok))
                else:
                    values.append(tok)
                tok = self._advance()
            # tok is now the Semicolon that ended the loop
            span = Span(
                start=first.span.start,
                end=tok.span.end,
                line=first.span.line,
                col=first.span.col,
            )
            return Statement(span=span, values=tuple(values))
        except IndexError:
            raise ParseError(
                "Unexpected end of input for statement", first.span)

    def _parse_negated(self, bang: Token) -> Negated:
        """
        Parse a negated node.

        The '!' has already been consumed and is passed in as bang.
        Advances once and dispatches through _parse_node — whatever node
        follows is wrapped in Negated.

            !192.168.1.0/24;    → Negated(Statement([Word(...)]))
            !{ 10.0.0.0/8; };  → Negated(Block([...]))

        A negated Block owns its closing ';' — consumed here since
        _parse_block only consumes up to and including '}'.
        A negated Statement already consumed its own ';'.
        """
        try:
            inner = self._parse_node(self._advance())
            if isinstance(inner, Negated):
                raise ParseError(
                    "Unexpected '!' after '!' — double negation is not valid",
                    bang.span,
                )
            if isinstance(inner, Block):
                tok = self._advance()
                if not isinstance(tok, Semicolon):
                    raise ParseError(
                        f"Expected ';' after negated block, "
                        f"got {type(tok).__name__} {tok.raw!r}",
                        tok.span,
                    )
        except IndexError:
            raise ParseError(
                "Unexpected end of input after '!'", bang.span)
        span = Span(
            start=bang.span.start,
            end=inner.span.end,
            line=bang.span.line,
            col=bang.span.col,
        )
        return Negated(span=span, inner=inner)

    def parse(self) -> Conf:
        """Parse the full token stream and return the root Conf node."""
        body: list[Statement | Block | Negated] = []
        try:
            tok = self._advance()
            start_span = tok.span
            while True:
                node = self._parse_node(tok)
                body.append(node)
                end_pos = node.span.end
                tok = self._advance()
        except IndexError:
            if not body:
                return Conf(span=Span(0, 0, 1, 1), body=())
            span = Span(
                start=start_span.start,
                end=end_pos,
                line=start_span.line,
                col=start_span.col,
            )
            return Conf(span=span, body=tuple(body))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse(text: str) -> Conf:
    """Parse a named.conf string and return the root Conf AST node."""
    return Parser(lex(text)).parse()
