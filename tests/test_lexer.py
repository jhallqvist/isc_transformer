from __future__ import annotations
import pytest
from isc.named.lexer import (
    lex, Lexer,
    Token, Word, Number, String, Bang, Comment,
    LeftBrace, RightBrace, Semicolon, Eof,
    Span, LexerError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def tokens(text: str) -> list[Token]:
    """Lex text and strip the trailing Eof for brevity."""
    result = lex(text)
    assert isinstance(result[-1], Eof)
    return result[:-1]


def only(text: str) -> Token:
    """Lex text and assert exactly one non-Eof token is produced."""
    result = tokens(text)
    assert len(result) == 1
    return result[0]


# ---------------------------------------------------------------------------
# Empty / whitespace input
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_empty_string(self):
        result = lex("")
        assert len(result) == 1
        assert isinstance(result[0], Eof)

    def test_whitespace_only(self):
        result = lex("   \t\n\r\n  ")
        assert len(result) == 1
        assert isinstance(result[0], Eof)

    def test_eof_span(self):
        result = lex("")
        eof = result[0]
        assert eof.span.start == 0
        assert eof.span.end == 0


# ---------------------------------------------------------------------------
# Single-character tokens
# ---------------------------------------------------------------------------

class TestPunctuation:
    def test_left_brace(self):
        assert isinstance(only("{"), LeftBrace)

    def test_right_brace(self):
        assert isinstance(only("}"), RightBrace)

    def test_semicolon(self):
        assert isinstance(only(";"), Semicolon)

    def test_bang(self):
        assert isinstance(only("!"), Bang)

    def test_sequence(self):
        result = tokens("{ } ;")
        assert [type(t) for t in result] == [LeftBrace, RightBrace, Semicolon]


# ---------------------------------------------------------------------------
# Words
# ---------------------------------------------------------------------------

class TestWords:
    def test_simple_keyword(self):
        tok = only("options")
        assert isinstance(tok, Word)
        assert tok.value == "options"

    def test_dotted_identifier(self):
        tok = only("example.com")
        assert isinstance(tok, Word)
        assert tok.value == "example.com"

    def test_ipv4_address(self):
        tok = only("192.168.1.1")
        assert isinstance(tok, Word)
        assert tok.value == "192.168.1.1"

    def test_cidr_prefix(self):
        tok = only("192.168.0.0/24")
        assert isinstance(tok, Word)
        assert tok.value == "192.168.0.0/24"

    def test_cidr_does_not_consume_comment(self):
        result = tokens("192.168.0.0/24;")
        assert isinstance(result[0], Word)
        assert result[0].value == "192.168.0.0/24"
        assert isinstance(result[1], Semicolon)

    def test_word_stops_at_comment(self):
        result = tokens("foo//comment")
        assert isinstance(result[0], Word)
        assert result[0].value == "foo"
        assert isinstance(result[1], Comment)

    def test_word_stops_at_block_comment(self):
        result = tokens("foo/*comment*/")
        assert isinstance(result[0], Word)
        assert result[0].value == "foo"
        assert isinstance(result[1], Comment)

    def test_ipv6_address(self):
        tok = only("2001:db8::1")
        assert isinstance(tok, Word)
        assert tok.value == "2001:db8::1"

    def test_boolean_yes(self):
        tok = only("yes")
        assert isinstance(tok, Word)
        assert tok.value == "yes"

    def test_boolean_no(self):
        tok = only("no")
        assert isinstance(tok, Word)
        assert tok.value == "no"


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------

class TestNumbers:
    def test_decimal(self):
        tok = only("255")
        assert isinstance(tok, Number)
        assert tok.value == 255
        assert tok.base == 10

    def test_decimal_zero(self):
        # bare 0 — matches octal regex only if followed by octal digits
        # 0 alone has no octal digits after it, so falls through to decimal
        tok = only("0")
        assert isinstance(tok, Number)
        assert tok.value == 0
        assert tok.base == 10

    def test_hex_lower(self):
        tok = only("0xff")
        assert isinstance(tok, Number)
        assert tok.value == 255
        assert tok.base == 16

    def test_hex_upper(self):
        tok = only("0XFF")
        assert isinstance(tok, Number)
        assert tok.value == 255
        assert tok.base == 16

    def test_hex_mixed_case(self):
        tok = only("0xDeAdBeEf")
        assert isinstance(tok, Number)
        assert tok.value == 0xDEADBEEF
        assert tok.base == 16

    def test_octal(self):
        tok = only("0123")
        assert isinstance(tok, Number)
        assert tok.value == 83
        assert tok.base == 8

    def test_octal_short(self):
        tok = only("010")
        assert isinstance(tok, Number)
        assert tok.value == 8
        assert tok.base == 8

    def test_octal_long(self):
        tok = only("037777777777")
        assert isinstance(tok, Number)
        assert tok.value == 0o37777777777
        assert tok.base == 8

    def test_hex_takes_priority_over_octal(self):
        # 0x prefix must be classified as hex, not octal
        tok = only("0x10")
        assert isinstance(tok, Number)
        assert tok.base == 16
        assert tok.value == 16

    def test_large_decimal(self):
        tok = only("4294967295")
        assert isinstance(tok, Number)
        assert tok.value == 4294967295
        assert tok.base == 10

    def test_raw_preserved(self):
        tok = only("0xff")
        assert tok.raw == "0xff"


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

class TestStrings:
    def test_simple_string(self):
        tok = only('"hello"')
        assert isinstance(tok, String)
        assert tok.value == "hello"

    def test_raw_includes_quotes(self):
        tok = only('"hello"')
        assert tok.raw == '"hello"'

    def test_empty_string(self):
        tok = only('""')
        assert isinstance(tok, String)
        assert tok.value == ""

    def test_string_with_spaces(self):
        tok = only('"hello world"')
        assert isinstance(tok, String)
        assert tok.value == "hello world"

    def test_string_with_special_chars(self):
        tok = only('"example.com; # comment"')
        assert isinstance(tok, String)
        assert tok.value == "example.com; # comment"

    def test_unterminated_string(self):
        with pytest.raises(LexerError) as exc_info:
            lex('"unterminated')
        assert "Unterminated string" in str(exc_info.value)

    def test_unterminated_string_span(self):
        with pytest.raises(LexerError) as exc_info:
            lex('"unterminated')
        assert exc_info.value.span.line == 1
        assert exc_info.value.span.col == 1


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

class TestComments:
    def test_line_comment_double_slash(self):
        tok = only("// this is a comment\n")
        assert isinstance(tok, Comment)

    def test_line_comment_hash(self):
        tok = only("# this is a comment\n")
        assert isinstance(tok, Comment)

    def test_block_comment(self):
        tok = only("/* this is a comment */")
        assert isinstance(tok, Comment)

    def test_block_comment_multiline(self):
        tok = only("/*\n  multiline\n  comment\n*/")
        assert isinstance(tok, Comment)

    def test_line_comment_at_eof(self):
        # comment with no trailing newline
        tok = only("// no newline at eof")
        assert isinstance(tok, Comment)

    def test_comment_raw_preserved(self):
        result = lex("// comment\n")
        assert result[0].raw == "// comment\n"

    def test_block_comment_raw_preserved(self):
        result = lex("/* hi */")
        assert result[0].raw == "/* hi */"

    def test_unterminated_block_comment(self):
        with pytest.raises(LexerError) as exc_info:
            lex("/* unterminated")
        assert "Unterminated block comment" in str(exc_info.value)

    def test_unterminated_block_comment_span(self):
        with pytest.raises(LexerError) as exc_info:
            lex("/* unterminated")
        assert exc_info.value.span.line == 1

    def test_comment_between_tokens(self):
        result = tokens("foo // comment\n bar")
        assert isinstance(result[0], Word)
        assert isinstance(result[1], Comment)
        assert isinstance(result[2], Word)
        assert result[0].value == "foo"
        assert result[2].value == "bar"

    def test_block_comment_between_tokens(self):
        result = tokens("foo /* comment */ bar")
        assert isinstance(result[0], Word)
        assert isinstance(result[1], Comment)
        assert isinstance(result[2], Word)


# ---------------------------------------------------------------------------
# Span / source location
# ---------------------------------------------------------------------------

class TestSpans:
    def test_first_token_col(self):
        tok = only("options")
        assert tok.span.col == 1

    def test_first_token_line(self):
        tok = only("options")
        assert tok.span.line == 1

    def test_token_after_newline_line(self):
        result = tokens("foo\nbar")
        assert result[1].span.line == 2

    def test_token_after_newline_col(self):
        result = tokens("foo\nbar")
        assert result[1].span.col == 1

    def test_col_after_whitespace(self):
        result = tokens("   foo")
        assert result[0].span.col == 4

    def test_span_start_end(self):
        tok = only("options")
        assert tok.span.start == 0
        assert tok.span.end == 7

    def test_span_after_whitespace(self):
        tok = only("   foo")
        assert tok.span.start == 3
        assert tok.span.end == 6

    def test_multiline_comment_line_tracking(self):
        result = tokens("/*\nline2\nline3\n*/\nword")
        word = result[1]
        assert isinstance(word, Word)
        assert word.span.line == 5


# ---------------------------------------------------------------------------
# Real named.conf fragments
# ---------------------------------------------------------------------------

class TestNamedConfFragments:
    def test_options_block(self):
        text = """
options {
    directory "/var/named";
    listen-on { 127.0.0.1; };
};
"""
        result = tokens(text)
        types = [type(t) for t in result]
        assert Word in types
        assert LeftBrace in types
        assert RightBrace in types
        assert Semicolon in types
        assert String in types

    def test_acl_with_negation(self):
        result = tokens("acl myacl { !192.168.1.0/24; };")
        assert isinstance(result[3], Bang)
        assert isinstance(result[4], Word)
        assert result[4].value == "192.168.1.0/24"

    def test_ttl_decimal(self):
        result = tokens("max-ttl 3600;")
        assert isinstance(result[1], Number)
        assert result[1].value == 3600

    def test_ttl_hex(self):
        result = tokens("max-ttl 0xe10;")
        assert isinstance(result[1], Number)
        assert result[1].value == 3600
        assert result[1].base == 16

    def test_mixed_comment_styles(self):
        text = "# hash\n// slash\n/* block */ word"
        result = tokens(text)
        assert isinstance(result[0], Comment)
        assert isinstance(result[1], Comment)
        assert isinstance(result[2], Comment)
        assert isinstance(result[3], Word)
        assert result[3].value == "word"

    def test_zone_block(self):
        text = 'zone "example.com" IN { type master; file "/etc/named/example.com"; };'
        result = tokens(text)
        assert isinstance(result[0], Word)
        assert result[0].value == "zone"
        assert isinstance(result[1], String)
        assert result[1].value == "example.com"

    def test_eof_always_last(self):
        for text in ["", "word", "{ }", "// comment\n", "/* block */"]:
            result = lex(text)
            assert isinstance(result[-1], Eof)
