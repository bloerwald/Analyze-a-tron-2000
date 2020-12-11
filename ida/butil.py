import ida_bytes
import ida_funcs
import ida_ida
import ida_nalt
import ida_name
import ida_search
import ida_segment
import ida_typeinf
import idc
import struct
import sys

def _find_sane (begin, end, pattern):
  flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT | ida_search.SEARCH_CASE
  result = ida_search.find_binary(begin, end, pattern, 16, flags)
  return result if result != idc.BADADDR else None

def find_segm_fixed (name):
  # ida_segments'getting segment by name returns a random one
  # segment_t.name is a bogus value
  # ... wtf? that "API" is a mess.
  res = []
  it = ida_segment.get_first_seg()
  while it:
    if ida_segment.get_segm_name(it) == name:
      res += [it]
    it = ida_segment.get_next_seg (it.start_ea + 1)
  return res

class SearchRange:
  absolutely_everything = [(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea)]
  @classmethod
  def segment(cls, name):
    seg = find_segm_fixed(name)
    if len(seg) == 0:
      raise Exception('unknown segment {}'.format(name))
    return [(s.start_ea, s.end_ea) for s in seg]

def find_pattern(pattern, search_range = SearchRange.absolutely_everything):
  remaining_search_range = []

  first_result = None
  for begin, end in search_range:
    if not first_result:
      print(hex(begin), hex(end), 'search', pattern)
      first_result = _find_sane (begin, end, pattern)
      if first_result:
        remaining_search_range += [(first_result + 1, end)]
    else:
      remaining_search_range += [(begin, end)]

  if not first_result:
    raise Exception ('unable to find pattern {}'.format (pattern))

  for begin, end in remaining_search_range:
    second_result = _find_sane (begin, end, pattern)
    if second_result:
      raise Exception ('found more than one occurence of pattern {}, {} and {}'.format (pattern, hex (first_result), hex (second_result)))

  return first_result

def find_string(string, search_range = SearchRange.absolutely_everything):
  return find_pattern (' '.join([hex(ord(c))[2:] for c in string]), search_range)

def find_pattern_all(pattern, search_range = SearchRange.absolutely_everything):
  addrs = []
  for begin, end in search_range:
    while True:
      addr = _find_sane (begin, end, pattern)
      if not addr:
        break
      addrs += [addr]
      begin = addr + 1
  return addrs

def find_string_all(string, search_range = SearchRange.absolutely_everything):
  return find_pattern_all (' '.join([hex(ord(c))[2:] for c in string]), search_range)

def mark_string(ea, name = None):
  strlen = len(idc.GetString (ea, -1))
  if strlen == 0:
    raise Exception('tried marking {} as string, but it isn\'t (len 0)'.format(hex(ea)))
  ida_bytes.del_items (ea,
                       ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES | ida_bytes.DELIT_NOCMT,
                       strlen + 1)
  ida_bytes.create_strlit(ea, strlen + 1, idc.get_inf_attr(idc.INF_STRTYPE))
  if name:
    ida_name.set_name (ea, name, ida_name.SN_CHECK)
  idc.apply_type (ea, idc.parse_decl('char const a[]', 0), idc.TINFO_DEFINITE)
  return idc.GetString (ea, -1)

def force_variable(ea, type, name):
  t = ida_typeinf.tinfo_t()
  ida_typeinf.parse_decl(t, None, '{} a;'.format(type), 0)
  ida_bytes.del_items (ea,
                       ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES | ida_bytes.DELIT_NOCMT,
                       t.get_size())
  ida_name.set_name (ea, name, ida_name.SN_CHECK)
  idc.apply_type (ea, idc.parse_decl('{} a;'.format(type), 0), idc.TINFO_DEFINITE)

def force_array(ea, type, name, count = None):
  t = ida_typeinf.tinfo_t()
  ida_typeinf.parse_decl(t, None, '{} a;'.format(type), 0)
  ida_bytes.del_items (ea,
                       ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES | ida_bytes.DELIT_NOCMT,
                       t.get_size() * (1 if count is None else count))
  ida_name.set_name (ea, name, ida_name.SN_CHECK)
  idc.apply_type (ea, idc.parse_decl('{} a[{}];'.format(type, '' if count is None else str(count)), 0), idc.TINFO_DEFINITE)

def force_function(ea, type, name):
  idc.MakeUnknown(ea, 1, idc.DOUNK_SIMPLE)
  idc.MakeFunction(ea)
  idc.MakeName(ea, name)
  idc.SetType(ea, type + ';')
  #ida_bytes.del_items (ea,
  #                     ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES | ida_bytes.DELIT_NOCMT,
  #                     1)
  #idc.MakeFunction(ea) # todo: ida_bytes version
  #ida_name.set_name (ea, name, ida_name.SN_CHECK)
  #idc.apply_type (ea, idc.parse_decl(type, 0), idc.TINFO_DEFINITE)



# a IDA clickable string for the given address
def eastr(ea):
  return hex(ea)[:-1]
