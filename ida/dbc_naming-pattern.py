import butil
import cutil
import tdbc
import tutil
import idc

# clientdb_base ctor: search any database name, xref to dbmeta, xref
# to the function using that, is mostly just one, the static ctor for
# the db object. db object ctor takes db* and meta*.
try:
  # beta, ptr
  DB2ConstructorLocation = butil.find_pattern ('4C 8B DC ' +
                                               '53 ' +
                                               '57 ' + # push rdi
                                               '48 81 EC A8 00 00 00 ' +
                                               '48 89 51 08 ' +
                                               '48 8D 05 ? ? ? ?  ' +
                                               '48 89 01 ' +
                                               '48 8B D9 ' +
                                               '33 C0 ' +
                                               '48 C7 41 78 08 00 00 00 ' +
                                                # todo: this is probably way too long.
                                               '48 89 41 10 ' +
                                               '48 89 41 18 ' +
                                               '48 89 41 20 ' +
                                               '48 89 41 28 ' +
                                               '48 89 41 30 ' +
                                               '48 89 41 38 ' +
                                               '48 89 41 40 ' +
                                               '48 89 41 48 ' +
                                               '48 89 41 50 ' +
                                               '48 89 41 58 ' +
                                               '48 89 41 60 ' +
                                               '48 89 41 68 ' +
                                               '48 89 81 88 00 00 00  ' +
                                               '48 89 81 80 00 00 00  ' +
                                               '48 89 81 98 00 00 00  ' +
                                               '48 89 81 A0 00 00 00  ' +
                                               '48 89 81 A8 00 00 00',
                                               butil.SearchRange.segment('.text'))
except:
  # retail
  DB2ConstructorLocation = butil.find_pattern ('40 53 ' +
                                               '48 83 EC 50 ' + # sub rsp, 50h
                                               '48 89 51 08 ' +
                                               '48 8D 05 ? ? ? ?  ' +
                                               '48 89 01 ' +
                                               '48 8B D9 ' +
                                               '33 C0 ' +
                                               '48 C7 41 78 08 00 00 00',
                                               butil.SearchRange.segment('.text'))

# function that is called from column getters to get field offset:
# search for string 'fieldIndex < m_meta->hotFixFieldCount', xref to
# that. there is likely multiple inlined copies but one that just does
# that assertion and accessing another m_meta field, returning it,
# which is called from all over the place
try:
  GetInMemoryFieldOffsetFromMetaLoc = butil.find_pattern ('48 89 5C 24 08 ' + # mov     [rsp+arg_10], rbx
                                                          '57 ' + # push rdi
                                                          '48 83 EC 40 ' + # sub     rsp, 40h
                                                          '48 8B 41 08 ' +
                                                          '48 8B F9 ' +
                                                          '8B DA ' +
                                                          '3B 50 14 ' +
                                                          '72 40 ' +
                                                          'C7 44 24 38 11 11 11 11 ' +
                                                          '4C 8D 0D',
                                                          butil.SearchRange.segment('.text'))
except:
  print('Unable to get GetInMemoryFieldOffsetFromMetaLoc, getters may be missing.')
  GetInMemoryFieldOffsetFromMetaLoc = None

# GetRowByID: start from a database object, preferably one that isn't
# used *that* much. go over xrefs. at least one is going to call a
# function that takes (db*, index, bool, bool*).
# Example:
# __int64 __fastcall sub_7FF761D3ED10(unsigned int a1)
# {
#   int v1; // eax
#   char v3; // [rsp+38h] [rbp+10h]
#
#   v1 = sub_7FF7619B6CF0(a1);
#   return sub_7FF761F1FE10((__int64)&db_CreatureModelData, v1, 0, &v3); <-- you are looking for this function
# }
try:
  RowReturnerLoc = butil.find_pattern ('48 89 5C 24 ? ' + # mov [rsp+?], rbx
                                       '55 ' + # push rbp
                                       '56 ' + # push rsi
                                       '57 ' + # push rdi
                                       '48 83 EC ? ' + # sub rsp, ?
                                       '41 C6 01 01 ' + # mov byte ptr [r9], 1
                                       '49 8B D9 ', # mov rbx, r9
                                        # todo: this is probably way too long? retail works fine without rest
                                        ## '80 B9 CD 01 00 00 00 ' +
                                        ## '41 0F B6 E8 ' +
                                        ## '8B F2 ' +
                                        ## '48 8B F9 ' +
                                        ## '75 ? ' +
                                        ## 'C7 44 24 38 11 11 11 11',
                                       butil.SearchRange.segment('.text'))
except:
  RowReturnerLoc = None

# clientdb_base dtor: take any clientdb_base ctor, reference the db
# object, the static ctor is usually first, the static dtor last. in
# the static dtor, there should be one function the db object is
# passed to. Alternatively go by the vtable that the ctor sets.
clientdb_base_dtor_loc = butil.find_pattern ('48 89 5C 24 08 ' + # mov [rsp+08], rbx
                                             '57 ' + # push rdi
                                             '48 83 EC ? ' +  # sub rsp, ?
                                             '33 FF ' + # xor edi, edi
                                             '48 8D 05 ? ? ? ? ' + # lea rax, ?
                                             '48 8b d9 ' + # mov rbx, rcx
                                             '48 89 01 ' + # mov [rcx], rax
                                             # todo: retail uses a different line here, 48 39 b9 90 01 00 00, so omit for now
                                             '40 38 b9 ? 01 00 00', # cmp [rcx+?EDh], dil
                                             butil.SearchRange.segment('.text'))

butil.set_name(DB2ConstructorLocation, tdbc.WowClientDB2_Base + "::ctor")
if GetInMemoryFieldOffsetFromMetaLoc:
  butil.set_name(GetInMemoryFieldOffsetFromMetaLoc, tdbc.WowClientDB2_Base + '::GetInMemoryFieldOffsetFromMeta')
if RowReturnerLoc:
  butil.set_name(RowReturnerLoc, tdbc.WowClientDB2_Base + "::GetRowByID")
butil.set_name (clientdb_base_dtor_loc, tdbc.WowClientDB2_Base + "::dtor")

dbobjects = {}

for codeRef in CodeRefsTo(DB2ConstructorLocation, 0):
  match = cutil.matches_any(codeRef,
                            ( [ (-0x0E, ['lea',  'rdx', '.*'                       ]),
                                (-0x07, ['lea',  'rcx', '.*'                       ]),
                                (+0x00, ['call',  tdbc.WowClientDB2_Base + '__ctor']),
                              ],
                              [ (0, 1, lambda val: val),
                                (1, 1, lambda val: val),
                              ],
                            ),
                           )

  if match is None:
    print ('static ctors: skipping {}: unknown pattern'.format (butil.eastr (codeRef)))
    continue
  # todo: check that we're not naming a bigger static ctor, e.g. by function size
  meta = match[0]
  dbobject = match[1]

  name = tdbc.make_db2meta (meta)

  butil.force_function (cutil.function_containing(codeRef), 'void f()', 'staticctor_db_{}'.format(name))
  butil.force_variable (dbobject, tdbc.WowClientDB2_Base, 'db_{}'.format(name))
  dbobjects[dbobject] = name

  for db2ObjectRef in XrefsTo(dbobject, 0):
    match = cutil.matches_any(db2ObjectRef.frm,
                              ( [ (+0x00, ['lea',  'rax', 'db_.*'  ]),
                                  (+0x07, ['retn'                  ]),
                                ],
                                [],
                              ),
                             )
    if match is None:
      continue

    butil.force_function (db2ObjectRef.frm,
                          '{db}* __fastcall a()'.format(db=tdbc.WowClientDB2_Base),
                          'GetDB{name}Pointer'.format(name=name))

for codeRef in CodeRefsTo(clientdb_base_dtor_loc, 0):
  match = cutil.matches_any(codeRef,
                            ( [ (-0x0B, ['lea',  'rcx', 'db_.*'                   ]),
                                (-0x04, ['add',  'rsp', '.*'                      ]),
                                (+0x00, ['jmp',  tdbc.WowClientDB2_Base + '__dtor']),
                              ],
                              [ (0, 1, lambda val: idc.get_name(val)[len('db_'):]),
                              ],
                            ),
                           )

  if match is None:
    continue
  # todo: check that we're not naming a bigger static dtor, e.g. by function size
  name = match[0]

  butil.set_name (cutil.function_containing(codeRef), 'staticdtor_db_{}'.format(name))

def has_build(needle, builds):
  for build in builds:
    if isinstance(build, tuple):
      begin, end = build
      if begin.major != end.major or begin.minor != end.minor or begin.patch != end.patch or begin.build > end.build:
        continue # todo: implement
      while begin != end:
        if needle == str(begin):
          return True
        begin.build += 1
    else:
      if str(build) == needle:
        return True

  return False

def init_column_names_and_make_rec_structs():
  inline_column_names = {}

  try:
    likely_wowdefs_path = os.path.dirname(os.path.realpath(__file__)) + '/WoWDBDefs'
    sys.path += [likely_wowdefs_path + '/code/Python']
    import dbd
  except Exception:
    print ('WARNING: NOT getting column names: unable to find WoWDBDefs directory')
    return inline_column_names

  user_agent_prefix = 'Mozilla/5.0 (Windows; U; %s) WorldOfWarcraft/'
  build = butil.get_cstring (butil.find_string (user_agent_prefix) + len(user_agent_prefix)).decode("utf-8")

  print(F"Parsing DBD directory {likely_wowdefs_path + '/definitions'} with build {build}")
  dbds = dbd.parse_dbd_directory(likely_wowdefs_path + '/definitions')

  for name, parsed in dbds.items():
    inline_column_names[name] = []

    columns = {}
    for column in parsed.columns:
      columns[column.name] = column
    assert(len(columns)==len(parsed.columns))

    for definition in parsed.definitions:
      if not has_build (build, definition.builds):
        continue

      lines = []
      has_string = False
      for entry in definition.entries:
        if 'noninline' in entry.annotation:
          continue

        meta = columns[entry.column]

        type_str = meta.type
        if type_str in ['uint', 'int']:
          type_str = '{}{}_t'.format (meta.type if not entry.is_unsigned else 'uint', entry.int_width if entry.int_width else 32)
        elif type_str in ['string', 'locstring']:
          type_str = 'dbc_' + type_str
          has_string = True
        else:
          assert (not entry.int_width)
          assert (not meta.foreign)

        inline_column_names[name] += [entry.column]
        array_str = '[{}]'.format(entry.array_size) if entry.array_size else ''
        lines += ['{} {}{};'.format(type_str, entry.column, array_str)]

      if 'table is sparse' in definition.comments and has_string:
        print('WARNING: omitting rec struct for {}: table is sparse and has string, the layout would be wrong!'.format(name))
      else:
        tutil.add_packed_type (name + 'Rec', ''.join(lines), tutil.ADD_TYPE.REPLACE)

  return inline_column_names

inline_column_names = init_column_names_and_make_rec_structs()

def make_column_getter_name(db, idx):
  if db in inline_column_names:
    return '{}::col_{}_{}'.format (db, int(idx), inline_column_names[db][int(idx)])
  else:
    return '{}::col_{}'.format (db, int(idx))

column_getters = {}

def column_getter_prologue_fun_0(base = -0x0A):
  return [ (base+0x00, ['call', 'GetDB.*Pointer']),
           (base+0x05, ['xor',  'edx', 'edx'    ]),
           (base+0x07, ['mov',  'rcx', 'rax'    ]),
           (base+0x0A, ['call', '.*'            ]),
         ]

def column_getter_prologue_fun_x(base = -0x0D):
  return [ (base+0x00, ['call', 'GetDB.*Pointer']),
           (base+0x05, ['mov',  'edx', '.*'     ]),
           (base+0x0A, ['mov',  'rcx', 'rax'    ]),
           (base+0x0D, ['call', '.*'            ]),
         ]

def column_getter_prologue_inline_0(base = -0x09):
  return [ (base+0x00, ['xor',  'edx', 'edx'  ]),
           (base+0x02, ['lea',  'rcx', 'db_.*']),
           (base+0x09, ['call', '.*'          ]),
         ]

def column_getter_prologue_inline_x(base = -0x0C):
  return [ (base+0x00, ['mov',  'edx', '.*'   ]),
           (base+0x05, ['lea',  'rcx', 'db_.*']),
           (base+0x0C, ['call', '.*'          ]),
         ]

column_getter_matcher_fun_0 = [ 0,
                                (0, 0, lambda val: idc.get_name(val)[len('GetDB'):-len('Pointer')]),
                              ]
column_getter_matcher_fun_x = [ (1, 1, lambda val: val),
                                (0, 0, lambda val: idc.get_name(val)[len('GetDB'):-len('Pointer')]),
                              ]
column_getter_matcher_inline_0 = [ 0,
                                   (1, 1, lambda val: idc.get_name(val)[len('db_'):]),
                                 ]
column_getter_matcher_inline_x = [ (0, 1, lambda val: val),
                                   (1, 1, lambda val: idc.get_name(val)[len('db_'):]),
                                 ]

def column_getter_epilogue_a(base = +0x05):
  return [ (base+0x00, ['mov',   'eax', 'eax'                 ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x06, ['add',   'rsp', '.*'                  ]),
           (base+0x0A, ['pop',   'rdi'                        ]),
           (base+0x0B, ['retn'                                ]),
         ]
def column_getter_epilogue_h(base = +0x05):
  return [ (base+0x00, ['mov',   'eax', 'eax'                 ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x07, ['add',   'rsp', '.*'                  ]),
           (base+0x0B, ['pop',   'rdi'                        ]),
           (base+0x0C, ['retn'                                ]),
         ]
def column_getter_epilogue_j(base = +0x05):
  return [ (base+0x00, ['mov',   'eax', 'eax'                 ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x07, ['add',   'rsp', '.*'                  ]),
           (base+0x0B, ['pop',   'rdi'                        ]),
           (base+0x0C, ['pop',   'rbp'                        ]),
           (base+0x0D, ['retn'                                ]),
         ]
def column_getter_epilogue_g(base = +0x05):
  return [ (base+0x00, ['mov',   'eax', 'eax'                 ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x06, ['mov',   'rbx', '.*'                  ]),
           (base+0x0B, ['add',   'rsp', '.*'                  ]),
           (base+0x0F, ['pop',   'rdi'                        ]),
           (base+0x10, ['retn'                                ]),
         ]
def column_getter_epilogue_l(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'           ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x07, ['add', 'rsp', '.*'            ]),
           (base+0x0B, ['pop', 'r14'                  ]),
           (base+0x0D, ['pop', 'rdi'                  ]),
           (base+0x0E, ['pop', 'rbp'                  ]),
           (base+0x0F, ['retn'                        ]),
         ]
def column_getter_epilogue_q(base = +0x05):
  return [ (base+0x00, ['mov', 'rbx', '\[rsp.*\]'           ]),
           (base+0x05, ['mov', 'eax', 'eax'                 ]),
           (base+0x07, ['movzx', 'eax', '.* ptr \[rax.*\]'      ]),
           (base+0x0C, ['add', 'rsp', '.*'                  ]),
           (base+0x10, ['pop', 'rdi'                        ]),
           (base+0x11, ['retn'                              ]),
         ]
def column_getter_epilogue_x(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'           ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]']),
           (base+0x07, ['add', 'rsp', '.*'            ]),
           (base+0x0B, ['pop', 'rdi'                  ]),
           (base+0x0C, ['pop', 'rbp'                  ]),
           (base+0x0D, ['pop', 'rbx'                  ]),
           (base+0x0E, ['retn'                        ]),
         ]

def column_getter_epilogue_d(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'          ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]']),
           (base+0x06, ['add', 'rsp', '.*'           ]),
           (base+0x0A, ['pop', 'rdi'                 ]),
           (base+0x0B, ['pop', 'rbp'                 ]),
           (base+0x0C, ['retn'                       ]),
         ]
def column_getter_epilogue_m(base = +0x05):
  return [ (base+0x00, ['mov', 'rbx', '\[rsp.*\]'           ]),
           (base+0x05, ['mov', 'eax', 'eax'                 ]),
           (base+0x07, ['mov', 'eax', '\[rax.*\]'      ]),
           (base+0x0B, ['add', 'rsp', '.*'                  ]),
           (base+0x0F, ['pop', 'rdi'                        ]),
           (base+0x10, ['retn'                              ]),
         ]

def column_getter_epilogue_e(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'                 ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]'         ]),
           (base+0x05, ['add', 'rsp', '.*'                  ]),
           (base+0x09, ['pop', 'rdi'                        ]),
           (base+0x0A, ['retn'                              ]),
         ]
def column_getter_epilogue_y(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'                 ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]'         ]),
           (base+0x06, ['add', 'rsp', '.*'                  ]),
           (base+0x0A, ['pop', 'rdi'                        ]),
           (base+0x0B, ['retn'                              ]),
         ]

def column_getter_epilogue_b(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'        ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]']),
           (base+0x05, ['mov', 'rbx', '\[rsp.*\]' ]),
           (base+0x0A, ['add', 'rsp', '.*'         ]),
           (base+0x0E, ['pop', 'rdi'               ]),
           (base+0x0F, ['retn'                     ]),
         ]
def column_getter_epilogue_i(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'           ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]']),
           (base+0x06, ['add', 'rsp', '.*'            ]),
           (base+0x0A, ['pop', 'r14'                  ]),
           (base+0x0C, ['pop', 'rdi'                  ]),
           (base+0x0D, ['pop', 'rbp'                  ]),
           (base+0x0E, ['retn'                        ]),
         ]
def column_getter_epilogue_t(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'           ]),
           (base+0x02, ['mov', 'eax', '\[rax.*\]']),
           (base+0x06, ['add', 'rsp', '.*'            ]),
           (base+0x0A, ['pop', 'rdi'                  ]),
           (base+0x0B, ['pop', 'rbp'                  ]),
           (base+0x0C, ['pop', 'rbx'                  ]),
           (base+0x0D, ['retn'                        ]),
         ]

def column_getter_epilogue_c(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x06, ['add',   'rsp',  '.*'              ]),
           (base+0x0A, ['pop',   'rdi'                     ]),
           (base+0x0B, ['retn'                             ]),
         ]
def column_getter_epilogue_f(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x07, ['add',   'rsp',  '.*'              ]),
           (base+0x0B, ['pop',   'rdi'                     ]),
           (base+0x0C, ['retn'                             ]),
         ]

def column_getter_epilogue_k(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x08, ['add',   'rsp',  '.*'              ]),
           (base+0x0C, ['pop',   'rdi'                     ]),
           (base+0x0D, ['pop',   'rbx'                     ]),
           (base+0x0E, ['retn'                             ]),
         ]
def column_getter_epilogue_n(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x07, ['add',   'rsp',  '.*'              ]),
           (base+0x0B, ['pop',   'rdi'                     ]),
           (base+0x0C, ['pop',   'rbx'                     ]),
           (base+0x0D, ['retn'                             ]),
         ]

def column_getter_epilogue_o(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x07, ['add',   'rsp',  '.*'              ]),
           (base+0x0B, ['pop',   'r14'                     ]),
           (base+0x0D, ['pop',   'rdi'                     ]),
           (base+0x0E, ['pop',   'rbx'                     ]),
           (base+0x0F, ['retn'                             ]),
         ]
def column_getter_epilogue_p(base = +0x05):
  return [ (base+0x00, ['mov',   'eax',  'eax'             ]),
           (base+0x02, ['movss', 'xmm0', 'dword ptr \[.*\]']),
           (base+0x08, ['add',   'rsp',  '.*'              ]),
           (base+0x0C, ['pop',   'r14'                     ]),
           (base+0x0E, ['pop',   'rdi'                     ]),
           (base+0x0F, ['pop',   'rbx'                     ]),
           (base+0x10, ['retn'                             ]),
         ]

def column_getter_epilogue_u(base = +0x05):
  return [ (base+0x00, ['mov', 'eax', 'eax'                 ]),
           (base+0x02, ['movzx', 'eax', '.* ptr \[rax.*\]'      ]),
           (base+0x06, ['movzx', 'eax', 'al']),
           (base+0x09, ['add', 'rsp', '.*'                  ]),
           (base+0x0D, ['pop', 'rdi'                        ]),
           (base+0x0E, ['retn'                              ]),
         ]

def column_getter_epilogue_r(base = +0x05):
  return [ (base+0x00, ['mov',  'rbx', '\[rsp+.*\]']),
           (base+0x05, ['mov',  'rsi', '\[rsp+.*\]']),
         ] + column_getter_epilogue_a (base+0x0A)
def column_getter_epilogue_s(base = +0x05):
  return [ (base+0x00, ['mov',  'rbx', '\[rsp+.*\]']),
         ] + column_getter_epilogue_a (base+0x05)
def column_getter_epilogue_v(base = +0x05):
  return [ (base+0x00, ['mov',  'rbx', '\[rsp+.*\]']),
           (base+0x05, ['mov',  'rsi', '\[rsp+.*\]']),
         ] + column_getter_epilogue_u (base+0x0A)
def column_getter_epilogue_w(base = +0x05):
  return [ (base+0x00, ['mov',  'rbx', '\[rsp+.*\]']),
           (base+0x05, ['mov',  'rsi', '\[rsp+.*\]']),
         ] + column_getter_epilogue_e (base+0x0A)
def column_getter_epilogue_z(base = +0x05):
  return [ (base+0x00, ['mov',  'rbx', '\[rsp+.*\]']),
           (base+0x05, ['mov',  'rsi', '\[rsp+.*\]']),
         ] + column_getter_epilogue_y (base+0x0A)

column_getter_patterns = []
def add_pattern(pro, matcher):
  global column_getter_patterns
  for epi in [column_getter_epilogue_a, column_getter_epilogue_b,
              column_getter_epilogue_c, column_getter_epilogue_d,
              column_getter_epilogue_e, column_getter_epilogue_f,
              column_getter_epilogue_g, column_getter_epilogue_h,
              column_getter_epilogue_i, column_getter_epilogue_j,
              column_getter_epilogue_k, column_getter_epilogue_l,
              column_getter_epilogue_m, column_getter_epilogue_n,
              column_getter_epilogue_o, column_getter_epilogue_p,
              column_getter_epilogue_q, column_getter_epilogue_r,
              column_getter_epilogue_s, column_getter_epilogue_t,
              column_getter_epilogue_u, column_getter_epilogue_v,
              column_getter_epilogue_w, column_getter_epilogue_x,
              column_getter_epilogue_y, column_getter_epilogue_z]:
    column_getter_patterns += [(pro() + epi(), matcher)]
add_pattern (column_getter_prologue_fun_0, column_getter_matcher_fun_0)
add_pattern (column_getter_prologue_fun_x, column_getter_matcher_fun_x)
add_pattern (column_getter_prologue_inline_0, column_getter_matcher_inline_0)
add_pattern (column_getter_prologue_inline_x, column_getter_matcher_inline_x)

# Name column getting functions based on the uncompressed column returner
if GetInMemoryFieldOffsetFromMetaLoc:
  for codeRef in CodeRefsTo(GetInMemoryFieldOffsetFromMetaLoc, 0):
    match = cutil.matches_any(codeRef, *column_getter_patterns)

    if match is None:
      print ('column getters: skipping {}: unknown pattern'.format (butil.eastr (codeRef)))
      continue

    new_name = make_column_getter_name(match[1], match[0])

    if not new_name in column_getters:
      column_getters[new_name] = []
    column_getters[new_name] += [cutil.function_containing(codeRef)]


column_getter_dbobj_first = [ (+0x00, ['mov',  'rax', '.*' ]), ]

def column_getter_dbobj_movs(base, mov, mov1_size):
  return [ (base+0x00, ['mov',  'rcx', '[rax+20h]'  ]),
           (base+0x04, ['mov',  'eax', '\[rcx+.*\]'   ]),
           (base+0x04 + mov1_size, [mov, 'eax', '.*']),
         ]

def column_getter_dbobj_epilogue(base, first_bonus = 0):
  return [ (base+0x00, ['add', 'rsp', '.*']),
           (base+0x04, ['pop', '.*']),
           (base+0x05+first_bonus, ['pop', '.*']),
           (base+0x06+first_bonus, ['pop', 'rbp']),
           (base+0x07+first_bonus, ['retn']),
         ]

def column_getter_dbobj_matcher(row):
  return [(row, 1, lambda val: val / 4),]

for dbobject, name in dbobjects.items():
  for xref in XrefsTo (dbobject + 8):
    codeRef = xref.frm
    match = cutil.matches_any(codeRef,
                              (   column_getter_dbobj_first
                                + [(+0x07, ['mov', 'rbx', '\[rsp.*\]']),]
                                + column_getter_dbobj_movs(+0x0F, 'movzx', 3) # 5
                                + column_getter_dbobj_epilogue(+0x1B, 1),
                                column_getter_dbobj_matcher(3),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'mov', 3) # 3
                                + column_getter_dbobj_epilogue(+0x11, 0),
                                column_getter_dbobj_matcher(2),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'mov', 2) # 3
                                + column_getter_dbobj_epilogue(+0x10, 0),
                                column_getter_dbobj_matcher(2),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'mov', 3) # 4
                                + [(+0x12, ['mov', 'rsi', '\[rsp.*\]']),]
                                + column_getter_dbobj_epilogue(+0x1A, 1),
                                column_getter_dbobj_matcher(2),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'movzx', 2) # 4
                                + column_getter_dbobj_epilogue(+0x11, 0),
                                column_getter_dbobj_matcher(2),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'movzx', 3) # 4
                                + column_getter_dbobj_epilogue(+0x12, 0),
                                column_getter_dbobj_matcher(2),
                              ),
                              (   column_getter_dbobj_first
                                + [(+0x07, ['mov', 'rbx', '\[rsp.*\]']),]
                                + column_getter_dbobj_movs(+0x0F, 'mov', 3) # 4
                                + column_getter_dbobj_epilogue(+0x1A, 1),
                                column_getter_dbobj_matcher(3),
                              ),
                              (   column_getter_dbobj_first
                                + column_getter_dbobj_movs(+0x07, 'movzx', 3) # 5
                                + [(+0x13, ['mov', 'rsi', '\[rsp.*\]']),]
                                + column_getter_dbobj_epilogue(+0x1B, 1),
                                column_getter_dbobj_matcher(2),
                              ),
                             )

    if match is None:
      continue

    new_name = make_column_getter_name (name, match[0])

    if not new_name in column_getters:
      column_getters[new_name] = []
    column_getters[new_name] += [cutil.function_containing(codeRef)]

for name, eas in column_getters.items():
  if len(eas) == 1:
    butil.set_name (eas[0], name)
  else:
    suff = ord('a')
    for ea in eas:
      butil.set_name (ea, '{}_{}'.format(name, chr(suff)))
      suff += 1

  # todo: set type of function to `${dbmeta[column].types} (dbRec-but-with-that-stupid-offset*)`
  # to help autoanalysis
