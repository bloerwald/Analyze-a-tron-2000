# WARNING: Before running this script be sure to run tdbc.py, which creates structures required by this script

from idautils import *
from idaapi import *
from idc import *
import ida_hexrays
import tdbc

def set_type(ea, type_str):
    _type = parse_decl(type_str, 0)
    apply_type(ea, _type, TINFO_DEFINITE)

def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
        else:
            break
        addr += 1
    return out

class varNameFinder_visitor_t(ida_hexrays.ctree_parentee_t):
    def __init__(self):
        ida_hexrays.ctree_parentee_t.__init__(self)
        # Mode 0 - finds a name of variable that holds the field number
        #          if the variable name consits of digits only, assume it's actual value
        # Mode l - finds a value that has been assigned to variable
        self.mode = 0
        self.fieldNum = -1
        self.varName = None
        return

    def tryDecimalAndHex(self, s):
        num = -1;
        #1. Test if string is number in decimal system
        #print "testing s = ", s
        try:
            num = int(s, 10);
            #print "num 10 = ", num
        except ValueError:
            pass
        #2. Test is string is number in hes
        if (num < 0):
            try:
                num = int(s, 16);
                #print "num 16 = ", num
            except ValueError:
                pass

        return num;


    def process(self, expr):
        #print expr
        if (self.mode == 0):
            op = expr.op
            if (op == ida_hexrays.cot_memref):
                exprStr = expr.print1(None)
                exprStr = ida_lines.tag_remove(exprStr)
                exprStr = ida_pro.str2user(exprStr)
                if ("].storage_type" in exprStr):
                    #Extract variable name from [varname].storage_type expression
                    m = re.search('\[(.+?)\]', exprStr)
                    if m:
                        found = m.group(1)

                        #Test if it's a straight number
                        self.fieldNum = self.tryDecimalAndHex(found);
                        if (self.fieldNum > -1):
                            # Value has been found quitting
                            return 1

                        self.varName = found
                        return 1

        if (self.mode == 1):
            if (expr.op == 2) :
                exprStr = expr.print1(None)
                exprStr = ida_lines.tag_remove(exprStr)
                exprStr = ida_pro.str2user(exprStr)
                if ((self.varName + " =") in exprStr):
                    try:
                        self.fieldNum = expr.y.n.value(expr.y.type)
                        return 1
                    except AttributeError:
                        #print "oops"
                        pass

        return 0

    def visit_insn(self, i):
        return self.process(i)

    def visit_expr(self, expr):
        return self.process(expr)

def findFirstFuncCall(ea):
    for (startea, endea) in Chunks(ea):
        for head in Heads(startea, endea):
            if idaapi.isCode(idaapi.getFlags(head)) and idaapi.is_call_insn(head):
                #print "funcCall", ":", "0cot_numx%08x"%(head)
                return head


#Find first entrance to DB2
def findWoWClient2Constructor():
    sampleDb2Name = "CreatureDisplayInfo"
    searchText = " ".join("{:02x}".format(ord(c)) for c in sampleDb2Name)+" 00"
    #    print searchText

    found = False
    ea = MinEA()
    maxEa = MaxEA()
    while (found!=True) and ea < maxEa:
        ea = FindBinary(ea+1, SEARCH_DOWN|SEARCH_NEXT, searchText)
        #        print hex(ea)
        for xref in XrefsTo(ea, ida_xref.XREF_ALL):
            #print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
            for xref2 in XrefsTo(xref.frm, ida_xref.XREF_ALL):
                #Got it.
                ea = xref2.frm
                print "reference inside creation of DB2 = ", hex(ea)
                found = True
                break


    if not found:
        return 0

    db2CreatorFunc = GetFunctionAttr(ea, FUNCATTR_START)
    print "db2CreatorFunc = ", hex(db2CreatorFunc)
    constructorCall = findFirstFuncCall(db2CreatorFunc)
    print "constructor call:", 	hex(constructorCall)
    constructorItself = get_operand_value(constructorCall, 0)
    return constructorItself

def findAndRenameFieldGetters(instanceGetter, dbName):
    for xref in XrefsTo(instanceGetter, ida_xref.XREF_ALL):
        if (XrefTypeName(xref.type) == "Code_Near_Call"):

            funcStart = GetFunctionAttr(xref.frm, FUNCATTR_START)

            testdec = idaapi.decompile(funcStart)
            opDict = testdec.body.details

            visitor = varNameFinder_visitor_t()
            visitor.apply_to(testdec.body, None)

            fieldNum = visitor.fieldNum

            #If fieldNum has not been found yet, but varname was found
            if ((fieldNum < 0) and (visitor.varName != None)):
                visitor.mode = 1
                visitor.apply_to(testdec.body, None)
                fieldNum = visitor.fieldNum

            # If field number was found - rename the getter
            if (fieldNum != -1):
                idc.MakeNameEx(funcStart, dbName+"DBInstance::GetField"+str(visitor.fieldNum), idc.SN_NOWARN)

def findAndRenameInstanceGetter(ea, dbName):
    for xref in XrefsTo(ea, ida_xref.XREF_ALL):
        if (XrefTypeName(xref.type) == "Data_Offset"):
            #        if (True):
            #Suppose the getter function is only 7 bytes long
            funcStart = GetFunctionAttr(xref.frm, FUNCATTR_START)
            funcEnd = GetFunctionAttr(xref.frm, FUNCATTR_END)
            #print "ea = ", hex(xref.frm), XrefTypeName(xref.type), funcEnd - funcStart
            if ((funcEnd - funcStart) == 8):
                print "Found getter: ", hex(funcStart), " for ", dbName
                prototype_details = idc.parse_decl("WowClientDB2_Base * __cdecl get()", idc.PT_SILENT)
                if prototype_details:
                    idc.apply_type(funcStart, prototype_details)
                    idc.set_name(funcStart, prototype_details[0])
                idc.MakeNameEx(funcStart, "get"+dbName+"DBInstance", idc.SN_NOWARN)
                findAndRenameFieldGetters(funcStart, dbName)

                return funcStart
    print "Getter not found for ", dbName
    return 0


#Get data from constructor and rename field accessors
def processConstructorCallAndDB(callEa):
    print "processing ", hex(callEa)
    db2CreatorFunc = GetFunctionAttr(callEa, FUNCATTR_START)
    testdec = idaapi.decompile(callEa)

    #We decompiled from the function call.
    #So the first elemet should be callargs
    opDict = testdec.body.details.at(0).details.operands
    if (("a" not in opDict ) or (not type(opDict["a"]) is carglist_t)):
        #This is constructor for creation of sparse DBs
        for xref in XrefsTo(db2CreatorFunc, ida_xref.XREF_ALL):
            #print xref
            if (XrefTypeName(xref.type) == "Code_Near_Call"):
                processConstructorCallAndDB(xref.frm)
        return

    arglist = testdec.body.details.at(0).details.operands["a"]

    #print cexpr_t.op_to_typename[arglist.at(0).x.op]

    op0 = 0
    op1 = 0
    op0Type = cexpr_t.op_to_typename[arglist.at(0).x.op]
    op1Type = cexpr_t.op_to_typename[arglist.at(0).x.op]

    #print "arglist.at(0).x ", cexpr_t.op_to_typename[arglist.at(0).x.op], arglist.at(0).x
    #print "arglist.at(1).x ", cexpr_t.op_to_typename[arglist.at(1).x.op], arglist.at(1).x

    if (op0Type == "obj"):
        op0 = arglist.at(0).x.obj_ea
    elif (op1Type == "memref"):
        op0 = arglist.at(0).x.m
    else:
        op0 = arglist.at(0).x.x.obj_ea

    if (op1Type == "obj"):
        op1 = arglist.at(1).x.obj_ea
    elif (op1Type == "memref"):
        op1 = arglist.at(1).x.m
    else:
        op1 = arglist.at(1).x.x.obj_ea

    print "dbInstance = ", hex(op0)
    print "meta = ", hex(op1)
    print "Fdid = ", Dword(op1+8)
    db2Name = get_string(Qword(op1))
    print "db2Name = ", db2Name

    idc.MakeNameEx(db2CreatorFunc, "create"+db2Name+"DBInstance", idc.SN_NOWARN)
    idc.MakeNameEx(op0, "g_"+db2Name+"DBInstance", idc.SN_NOWARN)
    idc.MakeNameEx(op1, "g_"+db2Name+"DBMeta", idc.SN_NOWARN)

    tdbc.make_db2meta (op1)

    findAndRenameInstanceGetter(op0, db2Name)

wowClientConstr = findWoWClient2Constructor()

for xref in XrefsTo(wowClientConstr, ida_xref.XREF_ALL):
    if (XrefTypeName(xref.type) == "Code_Near_Call"):
        processConstructorCallAndDB(xref.frm)
