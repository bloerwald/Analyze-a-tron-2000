import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import re
import struct

o_void  =      0  # No Operand
o_reg  =       1  # General Register (al,ax,es,ds...)    reg
o_mem  =       2  # Direct Memory Reference  (DATA)      addr
o_phrase  =    3  # Memory Ref [Base Reg + Index Reg]    phrase
o_displ  =     4  # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm  =       5  # Immediate Value          value
o_far  =       6  # Immediate Far Address  (CODE)  addr
o_near  =      7  # Immediate Near Address (CODE)  addr

shifts = ["sar", "sal", "shr", "shl"]
jumps = [ "ja"
  , "jb"
  , "jbe"
  , "jg"
  , "jge"
  , "jl"
  , "jle"
  , "jmp"
  , "jnb"
  , "jno"
  , "jnp"
  , "jns"
  , "jnz"
  , "jo"
  , "jp"
  , "js"
  , "jz"
  ]
jump_pairs = [ ("ja", "jbe")
       , ("jb", "jnb")
       , ("jg", "jle")
       , ("jl", "jge")
       , ("jo", "jno")
       , ("jp", "jnp")
       , ("js", "jns")
       , ("jz", "jnz")
       ]
movs = ["mov", "xchg"]

ida_api_is_new = False
try:
  import ida_auto
  ida_api_is_new = True
except ImportError:
  pass

user_pos = ida_kernwin.get_screen_ea()
after_function_before_user_pos = ida_funcs.get_prev_func(user_pos).end_ea + 1
before_function_after_user_pos = ida_funcs.get_next_func(user_pos).start_ea - 1
hopefully_a_sane_start_of_function = (after_function_before_user_pos & ~0x0F) + 0x10
make_fun_pos = None
if ida_bytes.is_code(ida_bytes.get_flags (hopefully_a_sane_start_of_function)):
  make_fun_pos = hopefully_a_sane_start_of_function

def re_analyze_relevant_range():
  ida_bytes.del_items(after_function_before_user_pos,
                      0,
                      before_function_after_user_pos - after_function_before_user_pos)
  if not make_fun_pos is None:
    assume_code_at(make_fun_pos)
  else:
    run_autoanalysis(after_function_before_user_pos, before_function_after_user_pos)

def run_autoanalysis(start, end = None):
  if not end:
    end = start + 1
  if ida_api_is_new:
    ida_auto.plan_and_wait(start, end)
    ida_auto.auto_wait()
  else:
    idc.AnalyzeArea(start, end)

def name_at(ea):
  result = None
  if ida_api_is_new:
    result = idc.get_name(ea)
  else:
    result = idc.Name(ea)
  if not result:
    result = "loc_" + hex(ea)
    result = result.replace("_0x", "_")
    result = result.replace("L", "")
  return result

def patch(ea, data):
  if ida_api_is_new:
    return ida_bytes.patch_bytes(ea, data)
  else:
    for b in data:
      idc.PatchByte(ea, struct.unpack('B', b)[0])
      ea += 1

def bytes(ea, count = None):
  if not count:
    count = idc.get_item_size(ea)
  result = []
  while count:
    result += [idc.Byte(ea)]
    count -= 1
    ea += 1
  return result

def nop(ea, c = None):
  print("nop (" + hex(ea) + ", " + (str(c) if c else "whole_instruction") + ")")
  if not c:
    c = idc.get_item_size(ea)
  while c:
    patch(ea, assemble(ea, "nop"))
    c -= 1
    ea += 1

def patch_ins(ea, asm):
  print("patch_ins (" + hex(ea) + ", '" + asm + "')")
  new_code = assemble(ea, asm)
  if available_at_including_current_ins(ea) < len(new_code):
    raise Exception("patching instruction at " + hex(ea) + " to " + asm + " requires more code than current instruction")
  nop(ea, available_at_including_current_ins(ea))
  patch(ea, new_code)
  return ea + len(new_code)

def available_at_including_current_ins(ea):
  return non_nop_after_ins(ea) - ea

def assemble(ea, what):
  succ, code = idautils.Assemble(ea, what)
  if not succ:
    raise Exception("failed to assemble " + what)
  return code

def loc_string_to_ea(loc, base):
  pattern = r"^(short )?(near )?(ptr )?((loc|unk|sub)_(?P<addr>[0-9A-Fa-f]+)|\$)(?P<add>\+[1-9])?$"
  match = re.match(re.compile(pattern), loc)
  if not match:
    return name_at(loc)
  if match.group("addr"):
    addr = int(match.group("addr"), 16)
  else:
    addr = base
  add = int(match.group("add"), 16) if match.group("add") else 0
  return addr + add
def jump_op_string_to_ea(ea):
  return loc_string_to_ea(idc.print_operand(ea,0), ea)

def redirect_jump(ea, target):
  print("redirect_jump (" + hex(ea) + ", " + hex(target) + ")")
  ida_bytes.del_items(target)
  run_autoanalysis(target)
  patch_ins(ea, idc.print_insn_mnem(ea) + " " + name_at(target))

def next_non_nop_NOT_JUMPING(ea):
  if idc.print_insn_mnem(ea) == "nop" or is_non_NOP_nop(ea):
    return next_non_nop_NOT_JUMPING (ea + idc.get_item_size(ea))
  return ea
def next_non_nop_FOLLOWING_JUMPS(ea):
  ea = next_non_nop_NOT_JUMPING(ea)
  if idc.print_insn_mnem(ea) == "jmp":
    target = jump_op_string_to_ea(ea)
    return next_non_nop_FOLLOWING_JUMPS(target) if target else ea
  return ea

def non_nop_after_ins(ea):
  return next_non_nop_FOLLOWING_JUMPS(ea + idc.get_item_size(ea))

def make_jump_unconditional(ea):
  print("make_jump_unconditional (" + hex(ea) + ")")
  target = jump_op_string_to_ea(ea)
  ida_bytes.del_items(target)
  run_autoanalysis(target)
  patch_ins(ea, "jmp " + name_at(target))

def is_non_NOP_nop(current_ea):
  # <mov> x, x
  if idc.print_insn_mnem(current_ea) in movs: # no flags affected
    if idc.print_operand(current_ea,0) == idc.print_operand(current_ea,1):
      return True
  # <shift> x, 0
  if idc.print_insn_mnem(current_ea) in shifts: # If the count is 0, the flags are not affected.
    if idc.get_operand_type(current_ea,1) == o_imm and idc.print_operand(current_ea,1) == "0":
      return True
  return False

def assume_code_at(ea):
  ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND)
  ida_auto.auto_make_code(ea)
  run_autoanalysis(ea)

def maybe_simplify(current_ea):
  # lol nope
  #if idc.print_insn_mnem(current_ea) == "wait":
  #  return lambda: nop(current_ea)

  # <mov> x, x   <shift> x, 0
  # ->
  # nop
  if is_non_NOP_nop(current_ea):
    return lambda: nop(current_ea)

  # {test,and,xor,or} x, y   # clears of and cf
  # {jnb, jno} A
  # ->
  # text x, y
  # jmp A
  if idc.print_insn_mnem(current_ea) in ["test", "and", "or", "xor"]:
    next_ea = non_nop_after_ins(current_ea)
    if idc.print_insn_mnem(next_ea) in ["jnb", "jno"] and jump_op_string_to_ea(next_ea) > next_ea:
      return lambda: make_jump_unconditional(next_ea)

  # clc
  # jnb A
  # ->
  # clc
  # jmp A
  if idc.print_insn_mnem(current_ea) == "clc":
    next_ea = non_nop_after_ins(current_ea)
    if idc.print_insn_mnem(next_ea) == "jnb":
      return lambda: make_jump_unconditional(next_ea)
  # stc
  # {jbe, jb} A
  # ->
  # stc
  # jmp A
  if idc.print_insn_mnem(current_ea) == "stc":
    next_ea = non_nop_after_ins(current_ea)
    if idc.print_insn_mnem(next_ea) in ["jbe", "jb"]:
      return lambda: make_jump_unconditional(next_ea)

  # A: test x, y    A: nops
  # A+a: nops       <jmp> B
  # <jmp> A+a       <jmp> A+a
  # B:
  # ->
  # A: test x, y
  # A+a: nops
  # <jmp> B
  # B:
  if idc.print_insn_mnem(current_ea) in jumps:
    mnem = idc.print_insn_mnem(current_ea)
    target = jump_op_string_to_ea(current_ea)
    if target < current_ea and (current_ea - target) < 10 and idc.print_insn_mnem(target) == '':
      assume_code_at(target)
      re_analyze_relevant_range()
      target = next_non_nop_NOT_JUMPING(target)
      if idc.print_insn_mnem(target) == mnem:
        actual_target = jump_op_string_to_ea(target)
        return lambda: redirect_jump(current_ea, actual_target)

  # A: <jmp> B
  # B: <jmp> C
  # ->
  # A: <jmp> C
  # B: <jmp> C
  if idc.print_insn_mnem(current_ea) in jumps:
    mnem = idc.print_insn_mnem(current_ea)
    target = jump_op_string_to_ea(current_ea)
    if target:
      if idc.print_insn_mnem(target) == "":
        assume_code_at(target)
        assume_code_at(current_ea)
        re_analyze_relevant_range()
      any_target = next_non_nop_FOLLOWING_JUMPS(target)
      maybe_jmp_target = next_non_nop_NOT_JUMPING(target)
      if idc.print_insn_mnem(any_target) == mnem:
        actual_target = jump_op_string_to_ea(any_target)
        return lambda: redirect_jump(current_ea, actual_target)
      elif idc.print_insn_mnem(maybe_jmp_target) == "jmp":
        actual_target = jump_op_string_to_ea(maybe_jmp_target)
        return lambda: redirect_jump(current_ea, actual_target)

  # A: <jmpa> B
  #    <jmpb> B
  # ->
  # A: jmp B
  #    <jmpb> B
  for a, b in [(lhs, rhs) for lhs, rhs in jump_pairs] + [(rhs, lhs) for lhs, rhs in jump_pairs]:
    if idc.print_insn_mnem(current_ea) == a:
      target_a = jump_op_string_to_ea(current_ea)
      next_ea = non_nop_after_ins(current_ea)
      if idc.print_insn_mnem(next_ea) == b:
        target_b = jump_op_string_to_ea(next_ea)
        if target_a == target_b:
          return lambda: make_jump_unconditional(current_ea)

  def starts_with(s, pre):
    return s[0:len(pre)] == pre

  # mov stack, constanta
  # <op> stack, constantb
  # ->
  # mov stack, constanta <op> constantb
  if idc.print_insn_mnem(current_ea) == "mov" \
     and starts_with(idc.print_operand(current_ea,0), "qword ptr [rbp+") \
     and idc.get_operand_type(current_ea,1) == o_imm:
    lhs = int(idc.print_operand(current_ea, 1).replace("h", ""), 16)
    next_ea = non_nop_after_ins(current_ea)
    op = idc.print_insn_mnem(next_ea)
    if op in ["xor", "add"] \
       and idc.print_operand(current_ea, 0) == idc.print_operand(next_ea, 0) \
       and idc.get_operand_type(next_ea,1) == o_imm:
      rhs = int(idc.print_operand(next_ea, 1).replace("h", ""), 16)
      result = 0
      if op == "xor":
        result = lhs ^ rhs
      elif op == "add":
        result = lhs + rhs
      else:
        raise Exception("unknown op " + op)

      # todo: this is raw monkey patching becuase i was unable to get it to assemble with qwords in the lhs..
      if result & 0xFFFFFFFF00000000 != 0xFFFFFFFF00000000 and \
         result & 0xFFFFFFFF00000000 != 0x0000000000000000:
        raise Exception(":(")
      if bytes(current_ea)[:3] != [72, 199, 133]: #, 216, 252, 255, 255, 55, 243, 255, 255]:
      #         mov qword    stack offset  value
        raise Exception(":((")

      return lambda: (nop(next_ea), patch(current_ea + 3 + 4, struct.pack('I', result & 0xFFFFFFFF)))

  return None


def reanalyze_range_begin(ea):
    return ida_funcs.get_prev_func(ea).end_ea + 1
def reanalyze_range_end(ea):
    return ida_funcs.get_next_func(ea).start_ea - 1

def simplify_as_much_as_possible(current_ea):
  action = maybe_simplify(current_ea)
  if not action:
    return []
  while action:
    action()
    run_autoanalysis(reanalyze_range_begin(current_ea), reanalyze_range_end(current_ea))
    action = maybe_simplify(current_ea)
  return [non_nop_after_ins(current_ea)]

for _ in [0, 1, 2]:
  leads = [user_pos]
  while leads:
    lead = leads[0]
    leads = leads[1:] + simplify_as_much_as_possible(lead)

  re_analyze_relevant_range()
