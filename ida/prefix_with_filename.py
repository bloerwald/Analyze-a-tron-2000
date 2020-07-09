import butil
import idautils
import idc
import re

settle_for_mediocre_names = False

prefixes = [(r'.*/Battle.net.aurora/(include|src)/', 'bna/'),
            (r'.*/Battle.net.labs/Base/source/base/', 'bnl/base/'),
            (r'.*/Battle.net.labs/bnl_checkout-.*/source/', 'bnl/checkout/'),
            (r'.*/Battle.net.labs/bnl_scene-.*/source/', 'bnl/scene/'),
            (r'.*/Battle.net.labs/bnl_scene_browser-.*/source/', 'bnl/scene_browser/'),
            (r'.*/Battle.net.labs/Downloader/(.*)/(source|include)/\1/', r'bnl/downloader/\1/'),
            (r'.*/Battle.net.labs/ShMem/shmem/source/', 'bnl/shmem/'),
            (r'.*/Battle.net.labs/TACT/(.*)/(source|include)/', r'bnl/tact/\1/'),
            (r'.*/Battle.net.lib-websocket/src/', 'bnl/websocket/'),
            (r'.*/Blizzard/blz/[0-9]*.[0-9]*.[0-9]*/(include|src)/blz/', 'blz/'),
            (r'.*/Blizzard/prism/[0-9]*.[0-9]*.[0-9]*/(.*)/(include|src)/', r'blz/prism/\1/'),
            (r'.*/Blizzard/tag(_rpc|)/(src|include)/', r'blz/tag\1/'),
            (r'.*/Contrib/', ''),
            (r'.*/lua-5.1/src/', 'lua/'),
            (r'.*/fmod/fmod4/(src|lib)/fmod_', 'fmod/'),
            (r'.*/fmod/fmod4/(src|lib)/', 'fmod/'),
            (r'.*/Engine/Source/Gx/(include|src)/(Gx/)*', 'Engine/Gx/'),
            (r'.*/google/protobuf/', 'protobuf/'),
            (r'.*/Storm/(H|Source)/', 'Storm/'),
            (r'.*/Engine/Source/Domino/(Include|Source)/Domino/', 'Engine/Domino/'),
            (r'.*/Engine/Source/Domino/(Include|Source)/', 'Engine/Domino/'),
            (r'.*/WoW/Common/', 'Wow/Common/'),
            (r'.*/WoW/Source/Wow', 'Wow/'),
            (r'.*/WoW/Source/', 'Wow/'),
            (r'.*/Mainline/Source/', 'Wow/Mainline/'),
            (r'.*/Engine/Source/', 'Engine/'),
            (r'.*/Build/src/', 'Wow/'),
]

def strip_buildserver_fs_prefix(filename):
  filename = filename.replace ('\\', '/')
  had_prefix = False
  for prefix, replacement in prefixes:
    repl = re.sub (prefix, replacement, filename)
    if repl != filename:
      filename = repl
      had_prefix = True
      break

  if not had_prefix:
    print('WARNING: New prefix?', filename)

  fn_symbolish = filename.replace (r'[-\.]', '_').replace ('/', '::')
  prefix = (os.path.splitext(filename)[0] + '/').replace (r'[-\.]', '_').replace ('/', '::')
  return filename.replace('/', '\\'), fn_symbolish, prefix

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
  if string.endswith('.inl') or string.endswith ('.h') or string.endswith ('.hpp') or string.endswith ('.H') or 'include' in string:
    return True
  return False
def forbidden_name(string):
  return '::' in string

names = dict()
mediocre_names = dict()

for filename_addr in butil.find_string_all('D:\\BuildServer\\WoW\\', butil.SearchRange.segment('.rdata')):
  filename = idc.GetString(filename_addr, -1)

  filename, fn_symbolish, prefix = strip_buildserver_fs_prefix (filename)
  butil.mark_string(filename_addr, 'filename_{}'.format (fn_symbolish))

  if forbidden_file(filename):
    if '\\work\\shared-checkout\\' in filename:
      print('skipping file:', filename)
    continue

  funs = set()
  for _, frm, _, _ in xrefs (filename_addr):
    addr = idc.get_func_attr(frm, idc.FUNCATTR_START)
    if addr != idc.BADADDR:
      funs.add (addr)

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
  MakeName (fun, candidates[0])
  if len(candidates) > 1:
    idc.MakeComm(fun, 'or ' + ' or '.join(candidates[1:]))
    print('mutiple function names for {} :('.format(', '.join(candidates)))
if settle_for_mediocre_names:
  for fun, candidates in mediocre_names.items():
    MakeName (fun, candidates[0] + '$med')
    if len(candidates) > 1:
      idc.MakeComm(fun, 'or ' + ' or '.join(candidates[1:]))
