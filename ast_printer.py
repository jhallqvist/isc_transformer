from isc.named.parser import parse
from isc.named.visitor import ASTPrinter

with open('named.conf', 'r') as infile:
    data = infile.read()

tree = parse(data)
print(tree.accept(ASTPrinter()))
