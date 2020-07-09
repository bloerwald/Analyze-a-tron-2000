import tdbc
# Config
DB2ConstructorLocation = 0x00007FF78302AA00
UncompressedColumnReturnerLoc = 0x00007FF782A72250

# Example:
# __int64 __fastcall sub_7FF761D3ED10(unsigned int a1)
# {
#   int v1; // eax
#   char v3; // [rsp+38h] [rbp+10h]
#
#   v1 = sub_7FF7619B6CF0(a1);
#   return sub_7FF761F1FE10((__int64)&db_CreatureModelData, v1, 0, &v3); <-- you are looking for this function
# }
RowReturnerLoc = 0x00007FF783030C30


# End of config

# Name DB2 constructors
MakeName(DB2ConstructorLocation, "ClientDB::Constructor")
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
for codeRef in CodeRefsTo(UncompressedColumnReturnerLoc, 0):
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
MakeName(RowReturnerLoc, "ClientDB::GetRowByID")
