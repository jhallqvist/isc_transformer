from __future__ import annotations
from collections.abc import Iterator
from dataclasses import dataclass
import re


__all__ = [
    "lex",
    "Token", "Word", "Number", "String", "Bang", "Comment",
    "LeftBrace", "RightBrace", "Semicolon", "Eof",
    "Span", "LexerError",
]


_RE_HEX = re.compile(r'0[xX][0-9a-fA-F]+')
_RE_OCT = re.compile(r'0[0-7]+')
_RE_DEC = re.compile(r'[0-9]+')


@dataclass(frozen=True)
class Span:
    """Source location of a token."""
    start: int
    end: int
    line: int
    col: int

    def __repr__(self) -> str:
        return f"Span({self.start}:{self.end}, line={self.line}, col={self.col})"


@dataclass(frozen=True)
class Token:
    span: Span
    raw: str

    @property
    def line(self) -> int:
        return self.span.line

    @property
    def col(self) -> int:
        return self.span.col


@dataclass(frozen=True)
class Word(Token):
    """Bare word: keyword, IP address, CIDR prefix, boolean, identifier …"""
    value: str

    def __repr__(self) -> str:
        return (f"Word({self.value!r}, line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class Number(Token):
    """
    ISC numeric literal.  Priority: hex → oct → dec.
      hex  0[xX][0-9a-fA-F]+   "0xff"  → value=255,  base=16
      oct  0[0-7]+           "0123"  → value=83,   base=8
      dec  [0-9]+              "255"   → value=255,  base=10
    """
    value: int
    base:  int

    def __repr__(self) -> str:
        return (f"Number({self.raw!r}, value={self.value}, base={self.base}, "
                f"line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class String(Token):
    """Double-quoted string.  raw includes the quotes; value has them stripped."""
    value: str

    def __repr__(self) -> str:
        return (f"String({self.value!r}, line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class Bang(Token):
    """Negation prefix  !"""
    def __repr__(self) -> str:
        return (f"Bang(line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class Comment(Token):
    """// … | # … | /* … */"""
    def __repr__(self) -> str:
        return (f"Comment(line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class LeftBrace(Token):
    """Opening brace  {"""
    def __repr__(self) -> str:
        return (f"LeftBrace(line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class RightBrace(Token):
    """Closing brace  }"""
    def __repr__(self) -> str:
        return (f"RightBrace(line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class Semicolon(Token):
    """Semicolon  ;"""
    def __repr__(self) -> str:
        return (f"Semicolon(line={self.span.line}, col={self.span.col}, "
                f"pos={self.span.start}:{self.span.end})")


@dataclass(frozen=True)
class Eof(Token):
    """End of input."""
    def __repr__(self) -> str:
        return f"Eof(line={self.span.line}, col={self.span.col}, pos={self.span.start})"


class LexerError(ValueError):
    """
    Raised for unterminated constructs (strings, block comments).
    Carries a Span for the start of the offending construct.
    """
    def __init__(self, message: str, span: Span) -> None:
        super().__init__(message)
        self.span = span

    def __str__(self) -> str:
        return (f"LexerError at line {self.span.line}, col {self.span.col}: "
                f"{super().__str__()}")


class Lexer:

    _WHITESPACE = frozenset(" \t\r\n")
    _WORD_STOP  = frozenset(' \t\r\n{};"#!')

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    def _col_at(self, pos: int) -> int:
        """returns the column position of a token"""
        return pos - self._text.rfind("\n", 0, pos)

    def _line_at(self) -> int:
        return self._text.count("\n", 0, self._pos) + 1

    def _make(self, cls: type[Token], start: int, line: int, **kwargs) -> Token: # type: ignore[no-untyped-def]
        """
        Construct a token of supplied token class spanning [start, self._pos).
        """
        span = Span(
            start=start, end=self._pos, line=line, col=self._col_at(start))
        return cls(span=span, raw=self._text[start:self._pos], **kwargs)

    def _char(self) -> str:
        """Consume and return one character.  Raises IndexError at EOF."""
        ch = self._text[self._pos]
        self._pos += 1
        return ch

    def _peek(self, n: int = 1) -> str:
        """Look ahead n characters without consuming.  Never raises."""
        return self._text[self._pos:self._pos + n]

    def _skip_whitespace(self) -> None:
        """
        Advance past all whitespace characters.
        Direct index access avoids the slice overhead of _peek().
        """
        try:
            while self._text[self._pos] in self._WHITESPACE:
                self._pos += 1
        except IndexError:
            pass

    def _read_line_comment(self) -> None:
        """
        Advance past a // or # line comment.
        self._pos must be at the first character after the comment marker.
        Advances to the start of the next line (consuming the \\n) or EOF.
        """
        try:
            while self._text[self._pos] != "\n":
                self._pos += 1
            self._pos += 1
        except IndexError:
            pass

    def _read_block_comment(self, start_span: Span) -> None:
        """
        Advance past a /* … */ block comment.
        The opening "/*" has been consumed.
        Raises LexerError if the comment is unterminated.
        """
        try:
            while True:
                ch = self._char()
                if ch == "*" and self._peek() == "/":
                    self._pos += 1       # consume the /
                    return
        except IndexError:
            raise LexerError("Unterminated block comment", start_span)

    def _read_string(self, start_span: Span) -> str:
        """
        Advance past a double-quoted string and return the decoded value.
        self._pos must be at the first character inside the opening quote.
        """
        start = self._pos
        try:
            while self._text[self._pos] != '"':
                self._pos += 1
            end = self._pos
            self._pos += 1
            return self._text[start:end]
        except IndexError:
            raise LexerError("Unterminated string literal", start_span)

    def _read_word(self) -> None:
        """
        Advance past a bare word (first character already consumed).

        Uses direct index scanning rather than per-character method calls.
        Stops at any _WORD_STOP character or at the start of // or /*.
        """
        try:
            while True:
                char = self._text[self._pos]
                if char in self._WORD_STOP:
                    break
                if char == "/" and self._peek(2) in ("//", "/*"):
                    break
                self._pos += 1
        except IndexError:
            pass

    def _classify_word(self, start: int, line: int) -> Token:
        """
        Classify the word text[start:self._pos] as a Number or Word.
        Called after _read_word has advanced self._pos.
        """
        word = self._text[start:self._pos]
        if _RE_HEX.fullmatch(word):
            return self._make(Number, start, line, value=int(word, 16), base=16)
        if _RE_OCT.fullmatch(word):
            return self._make(Number, start, line, value=int(word, 8),  base=8)
        if _RE_DEC.fullmatch(word):
            return self._make(Number, start, line, value=int(word, 10), base=10)
        return self._make(Word, start, line, value=word)

    def _next_token(self) -> Token:
        self._skip_whitespace()
        start = self._pos
        line  = self._line_at()

        try:
            ch = self._char()
        except IndexError:
            span = Span(start=start, end=start, line=line, col=self._col_at(start))
            return Eof(span=span, raw="")

        if ch == "{":  return self._make(LeftBrace, start, line)
        if ch == "}":  return self._make(RightBrace, start, line)
        if ch == ";":  return self._make(Semicolon,   start, line)
        if ch == "!":  return self._make(Bang,   start, line)

        if ch == '"':
            start_span = Span(start=start, end=start+1, line=line,
                              col=self._col_at(start))
            value = self._read_string(start_span)
            return self._make(String, start, line, value=value)

        if ch == "/" and self._peek() == "/":
            self._char()                    # consume second /
            self._read_line_comment()
            return self._make(Comment, start, line)

        if ch == "#":
            self._read_line_comment()
            return self._make(Comment, start, line)

        if ch == "/" and self._peek() == "*":
            start_span = Span(start=start, end=start+1, line=line,
                              col=self._col_at(start))
            self._char()                    # consume *
            self._read_block_comment(start_span)
            return self._make(Comment, start, line)

        # Bare word (keyword, identifier, IP, CIDR, path, …)
        self._read_word()
        return self._classify_word(start, line)

    def _tokenise_gen(self) -> Iterator[Token]:
        """Internal generator yielding tokens including Eof."""
        while True:
            tok = self._next_token()
            yield tok
            if isinstance(tok, Eof):
                break

    def tokenise(self) -> list[Token]:
        """Return all tokens including comments, ending with Eof."""
        return list(self._tokenise_gen())


def lex(text: str) -> list[Token]:
    """Tokenise a named.conf string and return all tokens."""
    return Lexer(text).tokenise()
