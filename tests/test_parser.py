from __future__ import annotations
import pytest
from isc.named.lexer import Word, Number, String
from isc.named.parser import (
    parse,
    Conf, Statement, Block, Negated,
    ParseError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def body(text: str) -> tuple:
    """Parse text and return the Conf body tuple."""
    return parse(text).body


def only(text: str) -> Statement | Block | Negated:
    """Parse text and assert exactly one top-level node is produced."""
    result = body(text)
    assert len(result) == 1
    return result[0]


def stmt(text: str) -> Statement:
    """Parse text, assert one Statement, and return it."""
    node = only(text)
    assert isinstance(node, Statement)
    return node


def words(node: Statement) -> list[str]:
    """Return the raw string of every Word token in a Statement's values."""
    return [v.raw for v in node.values if isinstance(v, Word)]


# ---------------------------------------------------------------------------
# Empty / whitespace input
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_empty_string(self):
        conf = parse("")
        assert isinstance(conf, Conf)
        assert len(conf.body) == 0

    def test_whitespace_only(self):
        assert len(body("   \t\n  ")) == 0

    def test_comment_only(self):
        assert len(body("// just a comment\n")) == 0

    def test_block_comment_only(self):
        assert len(body("/* just a comment */")) == 0

    def test_empty_conf_span(self):
        conf = parse("")
        assert conf.span.line == 1
        assert conf.span.col == 1


# ---------------------------------------------------------------------------
# Simple statements
# ---------------------------------------------------------------------------

class TestSimpleStatements:
    def test_single_keyword(self):
        s = stmt("recursion yes;")
        assert len(s.values) == 2
        assert isinstance(s.values[0], Word)
        assert s.values[0].value == "recursion"
        assert isinstance(s.values[1], Word)
        assert s.values[1].value == "yes"

    def test_keyword_only(self):
        # A statement can have just a keyword and a semicolon
        s = stmt("notify;")
        assert len(s.values) == 1
        assert s.values[0].value == "notify"

    def test_multiple_words(self):
        s = stmt("also-notify 192.168.1.1 192.168.1.2;")
        assert words(s) == ["also-notify", "192.168.1.1", "192.168.1.2"]

    def test_string_value(self):
        s = stmt('directory "/var/named";')
        assert isinstance(s.values[1], String)
        assert s.values[1].value == "/var/named"

    def test_decimal_number(self):
        s = stmt("max-cache-ttl 3600;")
        assert isinstance(s.values[1], Number)
        assert s.values[1].value == 3600
        assert s.values[1].base == 10

    def test_hex_number(self):
        s = stmt("max-cache-ttl 0xe10;")
        assert isinstance(s.values[1], Number)
        assert s.values[1].value == 0xe10
        assert s.values[1].base == 16

    def test_octal_number(self):
        s = stmt("max-cache-ttl 0755;")
        assert isinstance(s.values[1], Number)
        assert s.values[1].value == 0o755
        assert s.values[1].base == 8

    def test_raw_preserved(self):
        s = stmt("max-cache-ttl 0xff;")
        assert s.values[1].raw == "0xff"

    def test_multiple_statements(self):
        result = body("recursion yes;\nmax-ttl 3600;")
        assert len(result) == 2
        assert isinstance(result[0], Statement)
        assert isinstance(result[1], Statement)

    def test_comments_stripped(self):
        s = stmt("// comment\nrecursion yes; // trailing")
        assert len(s.values) == 2
        assert s.values[0].value == "recursion"

    def test_block_comment_stripped(self):
        s = stmt("recursion /* inline */ yes;")
        assert len(s.values) == 2


# ---------------------------------------------------------------------------
# Block statements
# ---------------------------------------------------------------------------

class TestBlocks:
    def test_simple_block(self):
        s = stmt("options { recursion yes; };")
        assert isinstance(s.values[0], Word)
        assert s.values[0].value == "options"
        assert isinstance(s.values[1], Block)

    def test_block_body_length(self):
        s = stmt("options { recursion yes; max-ttl 3600; };")
        b = s.values[1]
        assert len(b.body) == 2

    def test_block_inner_statement(self):
        s = stmt('options { directory "/var/named"; };')
        b = s.values[1]
        inner = b.body[0]
        assert isinstance(inner, Statement)
        assert inner.values[0].value == "directory"
        assert isinstance(inner.values[1], String)
        assert inner.values[1].value == "/var/named"

    def test_empty_block(self):
        s = stmt("match-clients {};")
        b = s.values[1]
        assert isinstance(b, Block)
        assert len(b.body) == 0

    def test_values_before_block(self):
        s = stmt('zone "example.com" IN { type master; };')
        assert isinstance(s.values[0], Word)
        assert s.values[0].value == "zone"
        assert isinstance(s.values[1], String)
        assert s.values[1].value == "example.com"
        assert isinstance(s.values[2], Word)
        assert s.values[2].value == "IN"
        assert isinstance(s.values[3], Block)

    def test_block_not_last_value(self):
        # Block can appear mid-statement followed by more tokens
        s = stmt("also-notify { 192.168.1.1; } port 5353;")
        assert isinstance(s.values[1], Block)
        assert isinstance(s.values[2], Word)
        assert s.values[2].value == "port"
        assert isinstance(s.values[3], Number)
        assert s.values[3].value == 5353

    def test_multiple_blocks_in_statement(self):
        s = stmt('view "internal" { match-clients { 192.168.0.0/24; }; recursion yes; };')
        assert isinstance(s.values[0], Word)
        assert isinstance(s.values[1], String)
        assert isinstance(s.values[2], Block)
        outer_block = s.values[2]
        inner_stmt = outer_block.body[0]
        assert inner_stmt.values[0].value == "match-clients"
        assert isinstance(inner_stmt.values[1], Block)

    def test_nested_block(self):
        text = 'logging { channel default_log { file "/var/log/named.log"; }; };'
        s = stmt(text)
        outer = s.values[1]
        inner_stmt = outer.body[0]
        assert inner_stmt.values[0].value == "channel"
        inner_block = inner_stmt.values[2]
        assert isinstance(inner_block, Block)
        assert inner_block.body[0].values[0].value == "file"

    def test_block_body_is_statement(self):
        s = stmt("options { recursion yes; };")
        b = s.values[1]
        assert all(isinstance(n, Statement) for n in b.body)


# ---------------------------------------------------------------------------
# Negated nodes
# ---------------------------------------------------------------------------

class TestNegated:
    def test_negated_word(self):
        s = stmt("acl x { !10.0.0.0/8; };")
        b = s.values[2]
        neg = b.body[0]
        assert isinstance(neg, Negated)
        assert isinstance(neg.inner, Statement)
        assert neg.inner.values[0].value == "10.0.0.0/8"

    def test_negated_cidr(self):
        s = stmt("acl x { !192.168.0.0/24; };")
        neg = s.values[2].body[0]
        assert isinstance(neg, Negated)
        assert neg.inner.values[0].value == "192.168.0.0/24"

    def test_negated_block(self):
        s = stmt("acl x { !{ 10.0.0.0/8; }; };")
        neg = s.values[2].body[0]
        assert isinstance(neg, Negated)
        assert isinstance(neg.inner, Block)
        assert neg.inner.body[0].values[0].value == "10.0.0.0/8"

    def test_negated_and_plain_mixed(self):
        s = stmt("acl x { 192.168.0.0/24; !10.0.0.0/8; };")
        b = s.values[2]
        assert isinstance(b.body[0], Statement)
        assert isinstance(b.body[1], Negated)

    def test_top_level_negated(self):
        # Negated can appear at top level too
        result = body("!192.168.1.0/24;")
        assert len(result) == 1
        assert isinstance(result[0], Negated)
        assert result[0].inner.values[0].value == "192.168.1.0/24"

    def test_negated_inner_is_statement(self):
        result = body("!recursion;")
        neg = result[0]
        assert isinstance(neg.inner, Statement)

    def test_multiple_negated_in_block(self):
        s = stmt("acl x { !10.0.0.0/8; !172.16.0.0/12; };")
        b = s.values[2]
        assert all(isinstance(n, Negated) for n in b.body)
        assert b.body[0].inner.values[0].value == "10.0.0.0/8"
        assert b.body[1].inner.values[0].value == "172.16.0.0/12"


# ---------------------------------------------------------------------------
# Spans
# ---------------------------------------------------------------------------

class TestSpans:
    def test_statement_line(self):
        result = body("recursion yes;\nmax-ttl 3600;")
        assert result[0].span.line == 1
        assert result[1].span.line == 2

    def test_statement_col(self):
        s = stmt("recursion yes;")
        assert s.span.col == 1

    def test_statement_span_includes_semicolon(self):
        # "recursion yes;" is 14 chars, semicolon at pos 13, end=14
        s = stmt("recursion yes;")
        assert s.span.start == 0
        assert s.span.end == 14

    def test_block_statement_span_includes_closing_semicolon(self):
        # span end should be after the final ';' of '};'
        text = 'acl "test1" {\n  1.1.1.1;\n};\n'
        s = only(text)
        assert s.span.end == 27       # end of ';' after '}'

    def test_conf_span_matches_last_node(self):
        text = 'acl "test1" {\n  1.1.1.1;\n};\n'
        conf = parse(text)
        assert conf.span.end == conf.body[-1].span.end

    def test_conf_span_start(self):
        conf = parse("recursion yes;")
        assert conf.span.start == 0
        assert conf.span.line == 1

    def test_block_span(self):
        s = stmt("options { recursion yes; };")
        b = s.values[1]
        # Block starts at '{' and ends at '}'
        assert s.span.start == 0
        assert isinstance(b, Block)

    def test_negated_span_starts_at_bang(self):
        result = body("!192.168.1.0/24;")
        neg = result[0]
        # Negated span should start at the '!' character (pos 0)
        assert neg.span.start == 0
        assert neg.span.col == 1


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrors:
    def test_unterminated_block(self):
        with pytest.raises(ParseError) as exc_info:
            parse("options { recursion yes;")
        assert "end of input" in str(exc_info.value).lower()

    def test_unterminated_block_span(self):
        with pytest.raises(ParseError) as exc_info:
            parse("options { recursion yes;")
        assert exc_info.value.span is not None

    def test_unterminated_statement(self):
        with pytest.raises(ParseError) as exc_info:
            parse("recursion yes")
        assert "end of input" in str(exc_info.value).lower()

    def test_orphan_right_brace(self):
        with pytest.raises(ParseError):
            parse("} orphan")

    def test_bare_semicolon_in_block(self):
        with pytest.raises(ParseError):
            parse("options { ; };")

    def test_bang_inside_statement(self):
        with pytest.raises(ParseError) as exc_info:
            parse("options !bad;")
        assert "!" in str(exc_info.value)

    def test_missing_semicolon_after_block(self):
        # Block inside block body must be followed by ';'
        with pytest.raises(ParseError):
            parse("options { inner { } };")

    def test_parse_error_has_span(self):
        with pytest.raises(ParseError) as exc_info:
            parse("} bad")
        error = exc_info.value
        assert hasattr(error, "span")
        assert error.span.line >= 1

    def test_parse_error_str(self):
        with pytest.raises(ParseError) as exc_info:
            parse("} bad")
        assert "ParseError at line" in str(exc_info.value)

    def test_unterminated_string_propagates(self):
        # LexerError from unterminated string should propagate through parser
        from isc.named.lexer import LexerError
        with pytest.raises(LexerError):
            parse('"unterminated')


# ---------------------------------------------------------------------------
# Real named.conf fragments
# ---------------------------------------------------------------------------

class TestNamedConfFragments:
    def test_options_block(self):
        text = """
options {
    directory "/var/named";
    listen-on { 127.0.0.1; };
    recursion yes;
};
"""
        result = body(text)
        assert len(result) == 1
        s = result[0]
        assert isinstance(s, Statement)
        assert s.values[0].value == "options"
        b = s.values[1]
        assert isinstance(b, Block)
        assert len(b.body) == 3

    def test_acl_with_mixed_entries(self):
        text = "acl trusted { 192.168.0.0/24; 10.0.0.0/8; !172.16.0.0/12; };"
        s = stmt(text)
        b = s.values[2]
        assert isinstance(b.body[0], Statement)
        assert isinstance(b.body[1], Statement)
        assert isinstance(b.body[2], Negated)

    def test_zone_block(self):
        text = 'zone "example.com" IN { type master; file "/etc/named/example.com"; };'
        s = stmt(text)
        assert s.values[0].value == "zone"
        assert isinstance(s.values[1], String)
        assert s.values[1].value == "example.com"
        assert s.values[2].value == "IN"
        b = s.values[3]
        assert isinstance(b, Block)
        assert len(b.body) == 2

    def test_full_config(self):
        text = """
options {
    directory "/var/named";
    listen-on { 127.0.0.1; };
    recursion yes;
    max-cache-ttl 0xe10;
};
acl trusted { 192.168.0.0/24; !10.0.0.0/8; };
zone "example.com" IN {
    type master;
    file "/etc/named/example.com";
};
"""
        result = body(text)
        assert len(result) == 3
        assert result[0].values[0].value == "options"
        assert result[1].values[0].value == "acl"
        assert result[2].values[0].value == "zone"

    def test_logging_with_nested_blocks(self):
        text = """
logging {
    channel default_log {
        file "/var/log/named.log";
        severity dynamic;
    };
};
"""
        s = stmt(text)
        outer = s.values[1]
        assert isinstance(outer, Block)
        channel_stmt = outer.body[0]
        assert channel_stmt.values[0].value == "channel"
        inner_block = channel_stmt.values[2]
        assert isinstance(inner_block, Block)
        assert len(inner_block.body) == 2

    def test_eof_always_produces_conf(self):
        for text in ["", "recursion yes;", "options { };", "// comment\n"]:
            result = parse(text)
            assert isinstance(result, Conf)

    def test_accept_returns_result(self):
        from isc.named.visitor import Visitor
        class Identity(Visitor):
            def visit_conf(self, n):      return "conf"
            def visit_statement(self, n): return "statement"
            def visit_block(self, n):     return "block"
            def visit_negated(self, n):   return "negated"

        v = Identity()
        assert parse("").accept(v) == "conf"
        assert parse("recursion yes;").body[0].accept(v) == "statement"
        assert parse("options { };").body[0].values[1].accept(v) == "block"
        assert parse("!10.0.0.0/8;").body[0].accept(v) == "negated"
