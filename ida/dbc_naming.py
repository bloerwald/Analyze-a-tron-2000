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

#TODO: Define local type through script, see bernd's hard drive
DBStruct = "ClientDB"

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
    SetType(dbObjectAddr, DBStruct)

    for db2ObjectRef in XrefsTo(dbObjectAddr, 0):
        if GetMnem(db2ObjectRef.frm) != "lea" or GetOpnd(db2ObjectRef.frm, 0) != "rax":
            continue

        if GetMnem(db2ObjectRef.frm + 7) != "retn":
            continue

        MakeUnknown(db2ObjectRef.frm, 1, DOUNK_SIMPLE)
        MakeFunction(db2ObjectRef.frm)
        functionName = "GetDB" + name + "Pointer"
        MakeName(db2ObjectRef.frm, functionName)
        SetType(db2ObjectRef.frm, DBStruct + " *__fastcall " + functionName + "()")

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


#TODO set below struct and maybe check if it fits because it can change per build
# struct __unaligned __declspec(align(1)) ClientDB
# {
#   _QWORD qword0;
#   _QWORD qword8;
#   _QWORD qword10;
#   _QWORD qword18;
#   _QWORD qword20;
#   _QWORD qword28;
#   _QWORD qword30;
#   _QWORD qword38;
#   _QWORD qword40;
#   _QWORD qword48;
#   _QWORD qword50;
#   _QWORD qword58;
#   _QWORD qword60;
#   _QWORD qword68;
#   _BYTE gap70[8];
#   _QWORD qword78;
#   _QWORD qword80;
#   _QWORD qword88;
#   _DWORD dword90;
#   _BYTE gap94[4];
#   _QWORD m_parentLookup;
#   _QWORD qwordA0;
#   _QWORD qwordA8;
#   _QWORD qwordB0;
#   _QWORD qwordB8;
#   _QWORD qwordC0;
#   _QWORD qwordC8;
#   _QWORD qwordD0;
#   _QWORD qwordD8;
#   _QWORD qwordE0;
#   _DWORD dwordE8;
#   _BYTE gapEC[4];
#   _QWORD qwordF0;
#   _QWORD qwordF8;
#   _QWORD qword100;
#   _QWORD qword108;
#   _QWORD qword110;
#   _QWORD qword118;
#   _BYTE gap120[16];
#   _QWORD qword130;
#   _QWORD qword138;
#   _QWORD qword140;
#   _QWORD qword148;
#   _QWORD qword150;
#   _QWORD qword158;
#   _QWORD qword160;
#   _QWORD qword168;
#   _QWORD qword170;
#   _QWORD qword178;
#   _QWORD qword180;
#   _QWORD qword188;
#   _QWORD qword190;
#   _QWORD qword198;
#   _QWORD qword1A0;
#   _DWORD dword1A8;
#   _DWORD dword1AC;
#   _BYTE gap1B0[8];
#   _QWORD qword1B8;
#   _QWORD qword1C0;
#   _QWORD qword1C8;
#   _BYTE byte1D0;
# };
