from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from isc.named.parser import (
    Node, Conf, Statement, Block, Negated,
)
from isc.named.lexer import Token, Word, Number, String, Bang


__all__ = [
    "Visitor",
    "PrettyPrinter",
    "ConfExtractor",
    "StatementSummary",
]


# ---------------------------------------------------------------------------
# Base visitor
# ---------------------------------------------------------------------------

class Visitor:
    """
    Base class for AST visitors.

    Subclasses override visit_conf, visit_block, visit_statement, and
    visit_negated to implement operations over the AST.

    Traversal is initiated by calling node.accept(visitor), which invokes
    the correct visit_* method directly via double dispatch — the node's
    type selects the method without any isinstance checks or string lookup.

    Two traversal helpers are provided:

        visit_children(node)  — calls accept on all child nodes and returns
                                their results as a list.  Use for functional
                                visitors that build up a result from sub-trees.

        traverse(node)        — visits every node in the tree depth-first,
                                ignoring return values.  Use for stateful
                                visitors that accumulate results as side effects.
    """

    def visit_conf(self, node: Conf) -> Any:
        raise NotImplementedError(
            f"{type(self).__name__} must implement visit_conf")

    def visit_block(self, node: Block) -> Any:
        raise NotImplementedError(
            f"{type(self).__name__} must implement visit_block")

    def visit_statement(self, node: Statement) -> Any:
        raise NotImplementedError(
            f"{type(self).__name__} must implement visit_statement")

    def visit_negated(self, node: Negated) -> Any:
        raise NotImplementedError(
            f"{type(self).__name__} must implement visit_negated")

    def visit_children(self, node: Node) -> list[Any]:
        """
        Call accept on all direct child nodes and return their results.

        For Conf and Block: accepts each item in body.
        For Negated:        accepts inner.
        For Statement:      accepts any Block values embedded in values.
        """
        if isinstance(node, (Conf, Block)):
            return [child.accept(self) for child in node.body]
        if isinstance(node, Negated):
            return [node.inner.accept(self)]
        if isinstance(node, Statement):
            return [v.accept(self) for v in node.values if isinstance(v, Block)]
        return []

    def traverse(self, node: Node) -> None:
        """
        Visit every node in the tree depth-first, ignoring return values.
        Use for stateful visitors that accumulate results as side effects.
        """
        node.accept(self)
        if isinstance(node, (Conf, Block)):
            for child in node.body:
                self.traverse(child)
        elif isinstance(node, Negated):
            self.traverse(node.inner)
        elif isinstance(node, Statement):
            for v in node.values:
                if isinstance(v, Block):
                    self.traverse(v)


# ---------------------------------------------------------------------------
# Example 1: PrettyPrinter
#
# A functional visitor that returns a formatted string representation of
# the AST.  Demonstrates the return-value style.
# ---------------------------------------------------------------------------

class PrettyPrinter(Visitor):
    """
    Produces a readable, indented string representation of a named.conf AST.

    Usage:
        tree = parse(text)
        print(tree.accept(PrettyPrinter()))
    """

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    def _ind(self, depth: int) -> str:
        return " " * (self._indent * depth)

    def visit_conf(self, node: Conf) -> str:
        return "\n".join(child.accept(self) for child in node.body)

    def visit_block(self, node: Block, depth: int = 0) -> str:
        if not node.body:
            return "{}"
        inner = "\n".join(
            self._ind(depth + 1) + self._visit_body_item(child, depth + 1)
            for child in node.body
        )
        return "{\n" + inner + "\n" + self._ind(depth) + "}"

    def _visit_body_item(self, node: Statement | Block | Negated, depth: int) -> str:
        if isinstance(node, Negated):
            return self._visit_negated_indented(node, depth)
        if isinstance(node, Statement):
            return self._visit_statement_indented(node, depth)
        if isinstance(node, Block):
            return self.visit_block(node, depth) + ";"
        raise NotImplementedError(f"Unexpected node type {type(node).__name__} in _visit_body_item")

    def visit_statement(self, node: Statement, depth: int = 0) -> str:
        return self._visit_statement_indented(node, depth)

    def _visit_statement_indented(self, node: Statement, depth: int) -> str:
        parts = []
        for v in node.values:
            if isinstance(v, Block):
                parts.append(self.visit_block(v, depth))
            else:
                parts.append(v.raw)
        return " ".join(parts) + ";"

    def visit_negated(self, node: Negated) -> str:
        return self._visit_negated_indented(node, 0)

    def _visit_negated_indented(self, node: Negated, depth: int) -> str:
        if isinstance(node.inner, Block):
            return "!" + self.visit_block(node.inner, depth) + ";"
        return "!" + self._visit_statement_indented(node.inner, depth)


# ---------------------------------------------------------------------------
# Example 2: ConfExtractor
#
# A stateful visitor that extracts structured data from the AST.
# Demonstrates the accumulate-state style.
# ---------------------------------------------------------------------------

@dataclass
class StatementSummary:
    """Structured summary of one named.conf statement."""
    keyword:   str
    args:      list[str] = field(default_factory=list)
    has_block: bool      = False
    negated:   bool      = False

    def __repr__(self) -> str:
        parts = [f"keyword={self.keyword!r}"]
        if self.args:      parts.append(f"args={self.args}")
        if self.has_block: parts.append("has_block=True")
        if self.negated:   parts.append("negated=True")
        return f"StatementSummary({', '.join(parts)})"


class ConfExtractor(Visitor):
    """
    Extracts top-level statement summaries from a Conf node.

    Usage:
        tree   = parse(text)
        result = tree.accept(ConfExtractor())
        for summary in result:
            print(summary)
    """

    def visit_conf(self, node: Conf) -> list[StatementSummary]:
        return [child.accept(self) for child in node.body]

    def visit_statement(self, node: Statement) -> StatementSummary:
        keyword = ""
        args: list[str] = []
        has_block = False
        for v in node.values:
            if isinstance(v, Block):
                has_block = True
            elif not keyword:
                keyword = v.raw
            else:
                args.append(v.raw)
        return StatementSummary(keyword=keyword, args=args, has_block=has_block)

    def visit_negated(self, node: Negated) -> StatementSummary:
        from typing import cast
        summary = cast(StatementSummary, node.inner.accept(self))
        summary.negated = True
        return summary

    def visit_block(self, node: Block) -> list[StatementSummary]:
        return [child.accept(self) for child in node.body]


# ---------------------------------------------------------------------------
# Example 3: ASTPrinter
#
# A functional visitor that renders the AST as an annotated tree using
# box-drawing characters, showing node types, token values, and spans.
#
# Example output:
#
#   Conf  [1:1 → 3:1]
#   ├── Statement  [1:1 → 1:14]
#   │   ├── Word  'recursion'
#   │   └── Word  'yes'
#   └── Statement  [2:1 → 2:16]
#       ├── Word  'max-ttl'
#       └── Number  3600  (base 10)
# ---------------------------------------------------------------------------

class ASTPrinter(Visitor):
    """
    Renders the AST as a human-readable tree with box-drawing characters.

    Shows node types, token values, and source spans so you can see both
    the structure and the provenance of every element.

    Usage:
        tree = parse(text)
        print(tree.accept(ASTPrinter()))
    """

    # Box-drawing pieces
    _BRANCH = "├── "
    _LAST   = "└── "
    _PIPE   = "│   "
    _SPACE  = "    "

    def _span(self, node: Node) -> str:
        s = node.span
        return f"[{s.line}:{s.col} → pos {s.start}:{s.end}]"

    def _token_label(self, tok: Token) -> str:
        if isinstance(tok, Word):
            return f"Word  {tok.value!r}"
        if isinstance(tok, Number):
            return f"Number  {tok.value}  (base {tok.base})"
        if isinstance(tok, String):
            return f"String  {tok.value!r}"
        if isinstance(tok, Bang):
            return "Bang  '!'"
        return f"{type(tok).__name__}  {tok.raw!r}"

    def _render(self, node: Node, prefix: str, is_last: bool) -> list[str]:
        """Recursively render a node and all its children."""
        connector = self._LAST if is_last else self._BRANCH
        child_prefix = prefix + (self._SPACE if is_last else self._PIPE)

        if isinstance(node, Conf):
            lines = [prefix + connector + f"Conf  {self._span(node)}"]
            children = list(node.body)
            for i, child in enumerate(children):
                lines += self._render(child, child_prefix, i == len(children) - 1)

        elif isinstance(node, Block):
            lines = [prefix + connector + f"Block  {self._span(node)}"]
            children = list(node.body)
            if not children:
                lines.append(child_prefix + self._LAST + "(empty)")
            for i, child in enumerate(children):
                lines += self._render(child, child_prefix, i == len(children) - 1)

        elif isinstance(node, Statement):
            lines = [prefix + connector + f"Statement  {self._span(node)}"]
            values = list(node.values)
            for i, v in enumerate(values):
                is_last_v = i == len(values) - 1
                if isinstance(v, Block):
                    lines += self._render(v, child_prefix, is_last_v)
                else:
                    tok_connector = self._LAST if is_last_v else self._BRANCH
                    lines.append(child_prefix + tok_connector + self._token_label(v))

        elif isinstance(node, Negated):
            lines = [prefix + connector + f"Negated  {self._span(node)}"]
            lines += self._render(node.inner, child_prefix, True)

        else:
            lines = [prefix + connector + f"{type(node).__name__}"]

        return lines

    def _render_root(self, node: Node) -> list[str]:
        """Render the root node without a leading connector."""
        child_prefix = ""

        if isinstance(node, Conf):
            lines = [f"Conf  {self._span(node)}"]
            children = list(node.body)
            for i, child in enumerate(children):
                lines += self._render(child, child_prefix, i == len(children) - 1)
            return lines

        # Non-Conf roots fall back to _render with empty prefix
        return self._render(node, "", True)

    def visit_conf(self, node: Conf) -> str:
        return "\n".join(self._render_root(node))

    def visit_block(self, node: Block) -> str:
        return "\n".join(self._render(node, "", True))

    def visit_statement(self, node: Statement) -> str:
        return "\n".join(self._render(node, "", True))

    def visit_negated(self, node: Negated) -> str:
        return "\n".join(self._render(node, "", True))
