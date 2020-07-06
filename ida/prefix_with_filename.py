import idautils
import idc

settle_for_mediocre_names = False

def strip_buildserver_fs_prefix(filename):
  if 'Source\\' in filename:
    filename = filename[filename.find ('Source\\')+len('Source\\'):]
  if 'src\\' in filename:
    filename = filename[filename.find ('src\\')+len('src\\'):]
  if 'source\\' in filename:
    filename = filename[filename.find ('source\\')+len('source\\'):]
  if '-branch\\' in filename:
    filename = filename[filename.find ('-branch\\')+len('-branch\\'):]
  filename = filename.replace ('-', '_')
  filename = filename.replace('\\', '::')
  return filename

def xrefs(to):
  return [(xref.__dict__['type'], xref.__dict__['frm'], xref.__dict__['to'], xref.__dict__['iscode']) for xref in idautils.XrefsTo (to, True)]

def forbidden_file(string):
  if not '\\work\\shared-checkout\\' in string:
    return True
  if 'Storm\\' in string and not '.cpp' in string or 'Storm\\H\\' in string:
    return True
  if 'Common\\Singleton' in string:
    return True
  return False
def last_effort_file(string):
  if string.endswith('.inl') or string.endswith ('.h'):
    return True
  if 'include\\' in string:
    return True
  return False
def forbidden_name(string):
  return '::' in string

names = dict()
mediocre_names = dict()

sc = idaapi.string_info_t()
for i in range(0,idaapi.get_strlist_qty()):
  idaapi.get_strlist_item(sc, i)
  filename = idaapi.get_ascii_contents(sc.ea,sc.length,sc.type)

  if forbidden_file(filename):
    if '\\work\\shared-checkout\\' in filename:
      print('skipping file:', filename)
    continue

  prefix = strip_buildserver_fs_prefix (filename)
  MakeName(sc.ea, 'filename_' + prefix)
  prefix = os.path.splitext(prefix)[0] + '::'
  prefix = prefix.replace ('.', '_')
  funs = set()
  for _, frm, _, _ in xrefs (sc.ea):
    funs.add (idc.get_func_attr(frm, idc.FUNCATTR_START))

  for fun in funs:
    curr_fun_name = idc.GetFunctionName(fun)
    new_fun_name = prefix + curr_fun_name
    if forbidden_name(curr_fun_name):
      #print('forbidden: {} "{}" to "{}"'.format(hex(fun), curr_fun_name,new_fun_name))
      continue

    nfnl = [new_fun_name]

    if last_effort_file(filename):
      if fun not in mediocre_names:
        mediocre_names[fun] = []
      mediocre_names[fun] += nfnl
    else:
      if fun not in names:
        names[fun] = []
      names[fun] += nfnl
      if fun in mediocre_names:
        del mediocre_names[fun]

for fun, candidates in names.items():
  MakeName(fun, candidates[0])
if settle_for_mediocre_names:
  for fun, candidates in mediocre_names.items():
    MakeName(fun, candidates[0])
