import tdbc

def find_pattern(pattern):
  first_result = idc.FindBinary (INF_BASEADDR, SEARCH_DOWN, pattern, 16)
  if first_result == BADADDR:
    raise Exception ('unable to find pattern {}'.format (pattern))
  # todo: this takes forever, but sanity *would* be nice :/
  ## second_result = idc.FindBinary (first_result + 1, SEARCH_DOWN, pattern, 16)
  ## if second_result != BADADDR:
  ##   raise Exception ('found more than one occurence of pattern {}, {} and {}'.format (pattern, hex (first_result), hex (second_result)))
  return first_result

# clientdb_base ctor: search any database name, xref to dbmeta, xref
# to the function using that, is mostly just one, the static ctor for
# the db object. db object ctor takes db* and meta*.
# todo: this is probably way too long.
DB2ConstructorLocation = find_pattern ('4C 8B DC 53 57 48 81 EC A8 00 00 00 48 89 51 08 48 8D 05 ? ? ? ? 48 89 01 48 8B D9 33 C0 48 C7 41 78 08 00 00 00 48 89 41 10 48 89 41 18 48 89 41 20 48 89 41 28 48 89 41 30 48 89 41 38 48 89 41 40 48 89 41 48 48 89 41 50 48 89 41 58 48 89 41 60 48 89 41 68 48 89 81 88 00 00 00 48 89 81 80 00 00 00 48 89 81 98 00 00 00 48 89 81 A0 00 00 00 48 89 81 A8 00 00 00')

# function that is called from column getters to get field offset:
# search for string 'fieldIndex < m_meta->hotFixFieldCount', xref to
# that. there is likely multiple inlined copies but one that just does
# that assertion and accessing another m_meta field, returning it,
# which is called from all over the place
GetInMemoryFieldOffsetFromMetaLoc = find_pattern ('48 89 5C 24 08 57 48 83 EC 40 48 8B 41 08 48 8B F9 8B DA 3B 50 14 72 40 C7 44 24 38 11 11 11 11 4C 8D 0D')

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
RowReturnerLoc = find_pattern ('48 89 5C 24 18 55 56 57 48 83 EC 60 41 C6 01 01 49 8B D9 80 B9 CD 01 00 00 00 41 0F B6 E8 8B F2 48 8B F9 75 ? C7 44 24 38 11 11 11 11')

MakeName(DB2ConstructorLocation, tdbc.WowClientDB2_Base + "::ctor")

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

# Name column getting functions based on the uncompressed column returner
for codeRef in CodeRefsTo(GetInMemoryFieldOffsetFromMetaLoc, 0):
    if GetDisasm(codeRef - 3) != "mov     rcx, rax":
        continue

    if GetDisasm(codeRef + 5) != "mov     eax, eax":
        continue

    colOffset = 0

    if GetDisasm(codeRef - 5) == "xor     edx, edx":
        colOffset = 5
        colIndex = 0
    elif GetMnem(codeRef - 8) == "mov" and GetOpnd(codeRef - 8, 0) == "edx":
        colOffset = 8
        colIndex = GetOperandValue(codeRef - 8, 1)
    else:
        print("something else", hex(codeRef))
        continue

    callAddr = codeRef - colOffset - 5
    db2Name = GetFunctionName(GetOperandValue(callAddr, 0))[5:-7]

    funcToRename = NextFunction(PrevFunction(callAddr))
    MakeName(funcToRename, db2Name + "::column_" + str(colIndex))

    #TODO Check function length to make sure we're not inline
    #TODO After that you should also check that mov after the dead mov to get data type and settype the function. I suggest determinedType f(_UNKNOWN*).

# Name generic row returner
MakeName(RowReturnerLoc, tdbc.WowClientDB2_Base + "::GetRowByID")
