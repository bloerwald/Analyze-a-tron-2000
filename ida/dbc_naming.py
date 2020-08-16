import butil
import cutil
import tdbc

# clientdb_base ctor: search any database name, xref to dbmeta, xref
# to the function using that, is mostly just one, the static ctor for
# the db object. db object ctor takes db* and meta*.
# todo: this is probably way too long.
DB2ConstructorLocation = butil.find_pattern ('4C 8B DC 53 57 48 81 EC A8 00 00 00 48 89 51 08 48 8D 05 ? ? ? ? 48 89 01 48 8B D9 33 C0 48 C7 41 78 08 00 00 00 48 89 41 10 48 89 41 18 48 89 41 20 48 89 41 28 48 89 41 30 48 89 41 38 48 89 41 40 48 89 41 48 48 89 41 50 48 89 41 58 48 89 41 60 48 89 41 68 48 89 81 88 00 00 00 48 89 81 80 00 00 00 48 89 81 98 00 00 00 48 89 81 A0 00 00 00 48 89 81 A8 00 00 00', butil.SearchRange.segment('.text'))

# function that is called from column getters to get field offset:
# search for string 'fieldIndex < m_meta->hotFixFieldCount', xref to
# that. there is likely multiple inlined copies but one that just does
# that assertion and accessing another m_meta field, returning it,
# which is called from all over the place
GetInMemoryFieldOffsetFromMetaLoc = butil.find_pattern ('48 89 5C 24 08 57 48 83 EC 40 48 8B 41 08 48 8B F9 8B DA 3B 50 14 72 40 C7 44 24 38 11 11 11 11 4C 8D 0D', butil.SearchRange.segment('.text'))

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
RowReturnerLoc = butil.find_pattern ('48 89 5C 24 18 55 56 57 48 83 EC 60 41 C6 01 01 49 8B D9 80 B9 CD 01 00 00 00 41 0F B6 E8 8B F2 48 8B F9 75 ? C7 44 24 38 11 11 11 11', butil.SearchRange.segment('.text'))

# clientdb_base dtor: take any clientdb_base ctor, reference the db
# object, the static ctor is usually first, the static dtor last. in
# the static dtor, there should be one function the db object is
# passed to. Alternatively go by the vtable that the ctor sets.
clientdb_base_dtor_loc = 0x07FF73D680AD0 # butil.find_pattern ('48 89 5C 24 08 57 48 83 EC 40 33 FF 48 8D 05 ? ? ? ? 48 8b d9 48 89 01 40 38 b9 cd 01 00 00', butil.SearchRange.segment('.text'))

MakeName(DB2ConstructorLocation, tdbc.WowClientDB2_Base + "::ctor")
MakeName(GetInMemoryFieldOffsetFromMetaLoc, tdbc.WowClientDB2_Base + '::GetInMemoryFieldOffsetFromMeta')
MakeName(RowReturnerLoc, tdbc.WowClientDB2_Base + "::GetRowByID")
MakeName (clientdb_base_dtor_loc, tdbc.WowClientDB2_Base + "::dtor")

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

  for db2ObjectRef in CodeRefsTo(dbobject, 0):
    match = cutil.matches_any(db2ObjectRef,
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
                              [ (0, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                           )

  if match is None:
    print ('static dtors: skipping {}: unknown pattern'.format (butil.eastr (codeRef)))
    continue
  # todo: check that we're not naming a bigger static dtor, e.g. by function size
  name = match[0]

  MakeName (cutil.function_containing(codeRef), 'staticdtor_db_{}'.format(name))

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
                                (0, 0, lambda val: Name(val)[len('GetDB'):-len('Pointer')]),
                              ]
column_getter_matcher_fun_x = [ (1, 1, lambda val: val),
                                (0, 0, lambda val: Name(val)[len('GetDB'):-len('Pointer')]),
                              ]
column_getter_matcher_inline_0 = [ 0,
                                   (1, 1, lambda val: Name(val)[len('db_'):]),
                                 ]
column_getter_matcher_inline_x = [ (0, 1, lambda val: val),
                                   (1, 1, lambda val: Name(val)[len('db_'):]),
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
for codeRef in CodeRefsTo(GetInMemoryFieldOffsetFromMetaLoc, 0):
  match = cutil.matches_any(codeRef, *column_getter_patterns)

  if match is None:
    print ('column getters: skipping {}: unknown pattern'.format (butil.eastr (codeRef)))
    continue

  # todo: dbd the actual column name
  new_name = '{}::column_{}'.format (match[1], match[0])

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

    # todo: dbd the actual column name
    new_name = '{}::column_{}'.format (name, match[0])

    if not new_name in column_getters:
      column_getters[new_name] = []
    column_getters[new_name] += [cutil.function_containing(codeRef)]

for name, eas in column_getters.items():
  if len(eas) == 1:
    MakeName (eas[0], name)
  else:
    suff = ord('a')
    for ea in eas:
      MakeName (ea, '{}_{}'.format(name, chr(suff)))
      suff += 1

  # todo: set type of function to `${dbmeta[column].types} (dbRec-but-with-that-stupid-offset*)`
  # to help autoanalysis
