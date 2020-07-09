import idc

def find_pattern(pattern):
  first_result = idc.FindBinary (idc.INF_BASEADDR, idc.SEARCH_DOWN, pattern, 16)
  if first_result == idc.BADADDR:
    raise Exception ('unable to find pattern {}'.format (pattern))
  # todo: this takes forever, but sanity *would* be nice :/
  ## second_result = idc.FindBinary (first_result + 1, idc.SEARCH_DOWN, pattern, 16)
  ## if second_result != idc.BADADDR:
  ##   raise Exception ('found more than one occurence of pattern {}, {} and {}'.format (pattern, hex (first_result), hex (second_result)))
  return first_result
