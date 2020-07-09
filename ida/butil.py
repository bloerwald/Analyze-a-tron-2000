import ida_bytes
import ida_ida
import ida_name
import ida_search
import ida_segment
import idc

def _find_sane (begin, end, pattern):
  flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT | ida_search.SEARCH_CASE
  result = ida_search.find_binary(begin, end, pattern, 16, flags)
  return result if result != idc.BADADDR else None

def _find_segm_fixed (name):
  # ida_segments'getting segment by name returns a random one
  # segment_t.name is a bogus value
  # ... wtf? that "API" is a mess.
  it = ida_segment.get_first_seg()
  while ida_segment.get_segm_name(it) != name and it:
    it = ida_segment.get_next_seg (it.start_ea + 1)
  return it

class SearchRange:
  absolutely_everything = None
  @classmethod
  def segment(cls, name):
    seg = _find_segm_fixed(name)
    if not seg:
      raise Exception('unknown segment {}'.format(name))
    return seg.start_ea, seg.end_ea

def _unpack_range(search_range):
  begin, end = ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea
  if search_range is not None:
    begin, end = search_range
  return begin, end

def find_pattern(pattern, search_range = None):
  begin, end = _unpack_range(search_range)

  first_result = _find_sane (begin, end, pattern)
  if not first_result:
    raise Exception ('unable to find pattern {}'.format (pattern))

  second_result = _find_sane (first_result + 1, end, pattern)
  if second_result:
    raise Exception ('found more than one occurence of pattern {}, {} and {}'.format (pattern, hex (first_result), hex (second_result)))

  return first_result

def find_pattern_all(pattern, search_range = None):
  begin, end = _unpack_range(search_range)

  addrs = []
  while True:
    addr = _find_sane (begin, end, pattern)
    if not addr:
      break
    addrs += [addr]
    begin = addr + 1
  return addrs

def find_string_all(string, search_range = None):
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
    ida_name.set_name (ea, name, ida_name.SN_CHECK | ida_name.SN_AUTO)
  idc.apply_type (ea, idc.parse_decl('char const a[]', 0), idc.TINFO_DEFINITE)
