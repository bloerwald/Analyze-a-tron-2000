import butil
import ida_bytes
import ida_segment

HEADER = butil.find_segm_fixed ('HEADER')
pdata = butil.find_segm_fixed ('.pdata')
rdata = butil.find_segm_fixed ('.rdata')

rdata.perm = rdata.perm & ~ida_segment.SEGPERM_WRITE

def rva2ea(rva):
  return HEADER.start_ea + rva

class RUNTIME_FUNCTION:
  off_start = 0x00
  off_end   = 0x04
  off_info  = 0x08
  size  = 0x0C
  def __init__(self, ea):
    self.ea = ea
  def start(self):
    return rva2ea(Dword (self.ea + self.off_start))
  def end(self):
    return rva2ea(Dword (self.ea + self.off_end))
  def info(self):
    return rva2ea(Dword (self.ea + self.off_info))
  def next(self):
    return RUNTIME_FUNCTION(self.ea + self.size)

for ea in range(pdata.start_ea, pdata.end_ea - RUNTIME_FUNCTION.size, RUNTIME_FUNCTION.size):
  f = RUNTIME_FUNCTION(ea)
  end = f.end()
  if end == rva2ea(0x0):
    break
  start = f.next().start()
  if start & 0xF != 0x0:
    continue
  if (end & ~0x0F) + 0x10 != start:
    continue
  if Byte(end - 1) != 0xC3:
    continue

  ida_bytes.del_items(end, ida_bytes.DELIT_NOUNAME | ida_bytes.DELIT_SIMPLE, start - end)
  ida_bytes.create_align(end, start - end, 4)
  #print(butil.eastr(ea), butil.eastr(f.end()), butil.eastr(f.next().start()))
