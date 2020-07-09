import butil
import cutil
import tdbc

# clientdb_base ctor: search any database name, xref to dbmeta, xref
# to the function using that, is mostly just one, the static ctor for
# the db object. db object ctor takes db* and meta*.
# todo: this is probably way too long.
DB2ConstructorLocation = butil.find_pattern ('4C 8B DC 53 57 48 81 EC A8 00 00 00 48 89 51 08 48 8D 05 ? ? ? ? 48 89 01 48 8B D9 33 C0 48 C7 41 78 08 00 00 00 48 89 41 10 48 89 41 18 48 89 41 20 48 89 41 28 48 89 41 30 48 89 41 38 48 89 41 40 48 89 41 48 48 89 41 50 48 89 41 58 48 89 41 60 48 89 41 68 48 89 81 88 00 00 00 48 89 81 80 00 00 00 48 89 81 98 00 00 00 48 89 81 A0 00 00 00 48 89 81 A8 00 00 00')

# function that is called from column getters to get field offset:
# search for string 'fieldIndex < m_meta->hotFixFieldCount', xref to
# that. there is likely multiple inlined copies but one that just does
# that assertion and accessing another m_meta field, returning it,
# which is called from all over the place
GetInMemoryFieldOffsetFromMetaLoc = butil.find_pattern ('48 89 5C 24 08 57 48 83 EC 40 48 8B 41 08 48 8B F9 8B DA 3B 50 14 72 40 C7 44 24 38 11 11 11 11 4C 8D 0D')

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
RowReturnerLoc = butil.find_pattern ('48 89 5C 24 18 55 56 57 48 83 EC 60 41 C6 01 01 49 8B D9 80 B9 CD 01 00 00 00 41 0F B6 E8 8B F2 48 8B F9 75 ? C7 44 24 38 11 11 11 11')

MakeName(DB2ConstructorLocation, tdbc.WowClientDB2_Base + "::ctor")
MakeName(GetInMemoryFieldOffsetFromMetaLoc, tdbc.WowClientDB2_Base + '::GetInMemoryFieldOffsetFromMeta')
MakeName(RowReturnerLoc, tdbc.WowClientDB2_Base + "::GetRowByID")

for codeRef in CodeRefsTo(DB2ConstructorLocation, 0):
    metaRef = codeRef - 14
    dbObjectRef = codeRef - 7

    # If these aren't lea then it's not a proper target
    # TODO: Handle sparse and other refs
    if GetMnem(dbObjectRef) != "lea" and GetMnem(metaRef) != "lea":
        continue

    # print(hex(codeRef), hex(dbObjectRef), hex(metaRef))
    dbObjectAddr = GetOperandValue(dbObjectRef, 1)
    metaTableAddr = GetOperandValue(metaRef, 1)
    # print("dbObject @ ", dbObjectAddr)
    # print("meta @ ", metaTableAddr)

    # Get address of DB2 name
    nameAddr = idc.Qword(metaTableAddr)

    # Get DB2 name
    name = idc.GetString(nameAddr, -1)
    print(name)

    MakeUnknown(metaTableAddr, 1, DOUNK_SIMPLE)
    MakeName(metaTableAddr, "dbMeta_" + name)
    SetType (metaTableAddr, tdbc.DBMeta)

    MakeUnknown(dbObjectAddr, 1, DOUNK_SIMPLE)
    MakeName(dbObjectAddr, "db_" + name)
    SetType(dbObjectAddr, tdbc.WowClientDB2_Base)

    for db2ObjectRef in XrefsTo(dbObjectAddr, 0):
        if GetMnem(db2ObjectRef.frm) != "lea" or GetOpnd(db2ObjectRef.frm, 0) != "rax":
            continue

        if GetMnem(db2ObjectRef.frm + 7) != "retn":
            continue

        MakeUnknown(db2ObjectRef.frm, 1, DOUNK_SIMPLE)
        MakeFunction(db2ObjectRef.frm)
        functionName = "GetDB" + name + "Pointer"
        MakeName(db2ObjectRef.frm, functionName)
        SetType(db2ObjectRef.frm, tdbc.WowClientDB2_Base + " *__fastcall " + functionName + "()")

column_getters = {}

# Name column getting functions based on the uncompressed column returner
for codeRef in CodeRefsTo(GetInMemoryFieldOffsetFromMetaLoc, 0):
  match = cutil.matches_any(codeRef,
                            ( [ (-0x0A, ['call', 'GetDB.*Pointer']),
                                (-0x05, ['xor',  'edx', 'edx'  ]),
                                (-0x03, ['mov',  'rcx', 'rax'  ]),
                                (+0x00, ['call', '.*'          ]),
                                (+0x05, ['mov',  'eax', 'eax'  ]),
                              ],
                              [ 0,
                                (0, 0, lambda val: Name(val)[len('GetDB'):-len('Pointer')]),
                              ],
                            ),
                            ( [ (-0x0D, ['call', 'GetDB.*Pointer']),
                                (-0x08, ['mov',  'edx', '.*'   ]),
                                (-0x03, ['mov',  'rcx', 'rax'  ]),
                                (+0x00, ['call', '.*'          ]),
                                (+0x05, ['mov',  'eax', 'eax'  ]),
                              ],
                              [ (1, 1, lambda val: val),
                                (0, 0, lambda val: Name(val)[len('GetDB'):-len('Pointer')]),
                              ],
                            ),
                            # sometimes the inliner manages to get rid
                            # of the function call :O
                            ( [ (-0x09, ['xor',  'edx', 'edx'  ]),
                                (-0x07, ['lea',  'rcx', 'db_.*']),
                                (+0x00, ['call', '.*'          ]),
                                (+0x05, ['mov',  'eax', 'eax'  ]),
                              ],
                              [ 0,
                                (1, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                            ( [ (-0x0C, ['mov',  'edx', '.*'   ]),
                                (-0x07, ['lea',  'rcx', 'db_.*']),
                                (+0x00, ['call', '.*'          ]),
                                (+0x05, ['mov',  'eax', 'eax'  ]),
                              ],
                              [ (0, 1, lambda val: val),
                                (1, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                            # sometimes function epilogue is reordered
                            # to be before the "useless move". as
                            # these are pretty random, one may need to
                            # add more variations here for other builds
                            ( [ (-0x09, ['xor',  'edx', 'edx'  ]),
                                (-0x07, ['lea',  'rcx', 'db_.*']),
                                (+0x00, ['call', '.*'          ]),
                                (+0x05, ['mov',  'rbx', '\[rsp+.*\]']),
                                (+0x0A, ['mov',  'rsi', '\[rsp+.*\]']),
                                (+0x0F, ['mov',  'eax', 'eax'  ]),
                              ],
                              [ 0,
                                (1, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                            ( [ (-0x0C, ['mov',  'edx', '.*'        ]),
                                (-0x07, ['lea',  'rcx', 'db_.*'     ]),
                                (+0x00, ['call', '.*'               ]),
                                (+0x05, ['mov',  'rbx', '\[rsp+.*\]']),
                                (+0x0A, ['mov',  'eax', 'eax'       ]),
                              ],
                              [ (0, 1, lambda val: val),
                                (1, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                            ( [ (-0x0C, ['mov',  'edx', '.*'        ]),
                                (-0x07, ['lea',  'rcx', 'db_.*'     ]),
                                (+0x00, ['call', '.*'               ]),
                                (+0x05, ['mov',  'rbx', '\[rsp+.*\]']),
                                (+0x0A, ['mov',  'rsi', '\[rsp+.*\]']),
                                (+0x0F, ['mov',  'eax', 'eax'       ]),
                              ],
                              [ (0, 1, lambda val: val),
                                (1, 1, lambda val: Name(val)[len('db_'):]),
                              ],
                            ),
                          )

  if match is None:
    print ('column getters: skipping {}: unknown pattern'.format (hex (codeRef)))
    continue

  # todo: check that we're not naming an inlined function, e.g. by function size

  new_name = '{}::column_{}'.format (match[1], match[0])

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
