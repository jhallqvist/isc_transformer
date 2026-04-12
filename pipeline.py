from isc.named.parser           import parse
from isc.named.semantic_visitor import SemanticVisitor
from isc.named.transformer      import TransformationVisitor
from isc.named.named_schema     import NAMED_CONF

conf      = parse(open("named.conf").read())
sv        = SemanticVisitor(NAMED_CONF, strict=False)
validated = sv.visit(conf)          # → ValidatedConf
tv        = TransformationVisitor()
result    = tv.transform(validated)  # → NamedConf

for err in sv.errors + tv.errors:
    print(err)
