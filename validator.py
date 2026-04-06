from isc.named.parser import parse
from isc.named.validator import SchemaValidator

with open('named.conf', 'r') as infile:
    data = infile.read()

tree = parse(data)
print(tree.accept(SchemaValidator()))
