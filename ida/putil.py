# name = enum('n1', 'n2', n3 = 4)
# name.n1 == 0
def enum(*sequential, **named):
  enums = dict(zip(sequential, range(len(sequential))), **named)
  return type('Enum', (), enums)
