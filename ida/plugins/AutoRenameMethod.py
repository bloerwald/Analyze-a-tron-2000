# This plugin automatically renames function based on struct type of argument in rcx register
# How to install: copy file into IDA/plugins folder

from __future__ import print_function

import ida_idaapi
import ida_typeinf
import ida_hexrays
import idaapi
import ida_name
import idc

# From enum RegNo
RCX_REG = 1

#Removes usercall calling convention, but doesnt keep order of arguments
# and messes the registers assigned to parameters
def fixFuncType(ea):
    funcEa = GetFunctionAttr(ea, FUNCATTR_START)
    cfunc = idaapi.decompile(funcEa)
    old_func_type = idaapi.tinfo_t()
    cfunc.get_func_type(old_func_type)

    fi = idaapi.func_type_data_t()
    if old_func_type.get_func_details(fi):
        if (fi.cc == idaapi.CM_CC_SPECIAL) or (fi.cc == idaapi.CM_CC_SPECIALE) or (fi.cc == idaapi.CM_CC_SPECIALP):
            fi.cc = idaapi.CM_CC_FASTCALL

            new_func_type = idaapi.tinfo_t()
            new_func_type.create_func(fi)

            idaapi.apply_tinfo2(funcEa, new_func_type, idaapi.TINFO_DEFINITE)

class autoRename_hooks_t(ida_hexrays.Hexrays_Hooks):
    def _shorten(self, cfunc):
        raw = str(cfunc)
        if len(raw) > 20:
            raw = raw[0:20] + "[...snipped...]"
        return raw

    def _format_lvar(self, v):
        parts = []
        if v:
            if v.name:
                parts.append("name=%s" % v.name)
            if v.cmt:
                parts.append("cmt=%s" % v.cmt)
            parts.append("width=%s" % v.width)
            parts.append("defblk=%s" % v.defblk)
            parts.append("divisor=%s" % v.divisor)
        return "{%s}" % ", ".join(parts)

    def lvar_type_changed(self, vu, v, tif):
        if (vu.cfunc):
            func_tif = ida_typeinf.tinfo_t()
            vu.cfunc.get_func_type(func_tif)

            funcdata = idaapi.func_type_data_t()
            got_data = func_tif.get_func_details(funcdata)

            if (not got_data):
                # self._log("Didnt get the data")
                pass

            lvars = vu.cfunc.get_lvars()
            for j in range(len(vu.cfunc.argidx)):
                # for i in vu.cfunc.argidx:
                i = vu.cfunc.argidx[j];
                if (lvars[i].name == v.name):
                    #self._log("lvar_type_changed: function argument changed = %s, index = %s, atype = %s" % (lvars[i].name, i, funcdata[j].argloc.atype()))
                    if(funcdata[i].argloc.atype() == 3):
                        #    self._log("lvar_type_changed: reg is : %s" %(funcdata[i].argloc.reg1()))
                        pass

                    if (funcdata[i].argloc.atype() != 3 or funcdata[i].argloc.reg1() != RCX_REG):
                        break

                    #self._log("applyName = %s" % (applyName))

                    firstPtrRemove = ida_typeinf.remove_pointer(tif)
                    #self._log("type name = %s" % (firstPtrRemove._print()))
                    #self._log("remove_pointer.is_ptr = %s" % (firstPtrRemove.is_ptr()))
                    #self._log("remove_pointer.is_struct = %s" % (firstPtrRemove.is_struct()))
                    if (firstPtrRemove.is_struct() and not firstPtrRemove.is_ptr()):
                        currentFuncName = ida_name.get_ea_name(vu.cfunc.entry_ea)
                        # self._log("before demangle current func name = %s" % (currentFuncName))
                        demangled = idc.Demangle(currentFuncName,idc.GetLongPrm(idc.INF_SHORT_DN))
                        if (demangled != None):
                            self._log("Overriding mangled name = %s" % (currentFuncName))
                            currentFuncName = demangled
                        # self._log("after demangle current func name = %s" % (currentFuncName))
                        tokens = currentFuncName.split("::")
                        if len(tokens) > 1:
                            currentFuncName = tokens[1]
                        currentFuncName = currentFuncName.split("(")[0]
                        # self._log("current func name = %s" % (currentFuncName))
                        idc.MakeNameEx(vu.cfunc.entry_ea, firstPtrRemove._print()+"::"+currentFuncName, idc.SN_NOWARN)
                        idaapi.autoWait()
                        # self._log("Decomp Res : %s" % idaapi.decompile(vu.cfunc.entry_ea))
                        idaapi.refresh_idaview_anyway()
                        vu.refresh_ctext()
                        idaapi.refresh_idaview_anyway()
                        vu.refresh_ctext()
                        vu.refresh_view(True)

                        current_widget = idaapi.get_current_widget()
                        vu1 = idaapi.get_widget_vdui(current_widget)
                        if vu1:
                            vu1.refresh_ctext()
                    break

        #self._log("lvar_type_changed: vu=%s, v=%s, tinfo=%s" % (vu, self._format_lvar(v), tif._print()))
        return 1

    def _log(self, msg):
        print("### %s" % msg)
        return 0


class autoRenamePlugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "This is a comment"
    help = "This is help"
    wanted_name = "Auto Rename plugin"
    wanted_hotkey = "Alt-F8"
    autoRenameHook = None
    def init(self):
        # idaapi.msg("init() called!\n")
        self.autoRenameHook = autoRename_hooks_t()
        self.autoRenameHook.hook()
        print("Auto rename method hook installed")

        return idaapi.PLUGIN_KEEP
    def run(self, arg):
        # idaapi.msg("run() called with %d!\n" % arg)
        pass
    def term(self):
        # idaapi.msg("term() called!\n")
        self.autoRenameHook.unhook()

def PLUGIN_ENTRY():
    return autoRenamePlugin_t()



