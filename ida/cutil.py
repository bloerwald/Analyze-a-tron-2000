import ida_lines
import ida_ua
import idc
import re

# matches (addr, [(-offset, ['mnem', 'op1', 'op2'])...], [(req_index, operand_index, function (value) -> value)])
# will return
# - None if the requirements were not matched at that address
# - a list of the values extracted by the given functions
# a gets tuple may be replaced with a constant, i.e. `[(reqi, opi, fun), 0,]` will return `[fun(reqi[opi]), 0]`
#
# Example:
#  matches(ea, [(0, ['call', 'Get.*']), (5, ['xor', 'rax', 'rax'])], [(0, 1, lambda val: Name(val)[len('Get'):])])
# will get you what is gotten and discarded right after
def matches(ea, reqs, gets):
  results = []
  for offs, ins in reqs:
    mnem = ida_lines.tag_remove(ida_ua.print_insn_mnem(ea + offs) or '')
    if ins[0] != mnem:
      return None
    i = 0
    for arg in ins[1:]:
      opnd = ida_lines.tag_remove(ida_ua.print_operand (ea + offs, i) or '')
      if opnd != arg and re.match('^' + arg + '$', opnd) is None:
        return None
      i += 1
  for get in gets:
    if type (get) == tuple:
      reqi, opi, fun = get
      results += [fun(idc.get_operand_value(ea + reqs[reqi][0], opi))]
    else:
      results += [get]
  return results

# patterns shall be tuple of reqs, gets as for matches(). first match wins. otherwise None.
def matches_any(ea, *patterns):
  for reqs, gets in patterns:
    values = matches (ea, reqs, gets)
    if values is not None:
      return values
  return None

def function_containing(ea):
  return idc.get_next_func(idc.get_prev_func(ea))
