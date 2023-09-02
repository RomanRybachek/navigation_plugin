import idaapi
import idc
import ida_lines
import idautils

from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def check_import_several_functions(ea, obj: FuncInfo):
    s = list(obj.strings)
    s_f = [b"PsGetVersion", b"WmiTraceMessage", b"WmiQueryTraceInformation",
           b"EtwRegisterClassicProvider", b"EtwUnregister"]
    c = 0
    for i in s:
        s_type = idc.get_str_type(i)
        content = idc.get_strlit_contents(i, -1, s_type)
        print(content)
        if content in s_f:
            c += 1
    if c == 5:
        return RULE_TRUE
    else:
        return RULE_FALSE


def check_RtlQueryRegistryValues(ea, obj: FuncInfo):
    if fingerprint(obj, 2, 3, None, True, 0, None, 1) == False:
        return RULE_FALSE

    s_ea = list(obj.strings)[0]
    s_type = idc.get_str_type(s_ea)
    s = idc.get_strlit_contents(s_ea, -1, s_type)
    if s == b"RtlQueryRegistryValuesEx":
        return RULE_TRUE
    else:
        return RULE_FALSE


def check_memset(ea, obj: FuncInfo):
    if fingerprint(obj, 7, None, 1, True, None, 1, None) == False:
        return RULE_FALSE
    ins = list(idautils.FuncItems(ea))
    line = idc.GetDisasm(ins[2])
    if line.find("101010101010101") != -1:
        return RULE_TRUE
    return RULE_FALSE


def check_memmove(ea, obj: FuncInfo):
    if fingerprint(obj, 23, 0, 0, True, None, 0, 0) == False:
        return RULE_FALSE
    ins = list(idautils.FuncItems(ea))
    jb = idc.GetDisasm(ins[2])
    ja = idc.GetDisasm(ins[4])
    if jb.find("jb") != -1 and ja.find("ja") != -1:
        return RULE_TRUE


def rule_entry(ea, obj: FuncInfo):
    if check_RtlQueryRegistryValues(ea, obj) == RULE_TRUE:
        return rule_exit(RULE_TRUE, ea, obj, "nav_RtlQueryRegistryValues")
    elif check_memset(ea, obj) == RULE_TRUE:
        return rule_exit(RULE_TRUE, ea, obj, "nav_memset")
    elif check_memmove(ea, obj) == RULE_TRUE:
        return rule_exit(RULE_TRUE, ea, obj, "nav_memmove")
    elif check_import_several_functions(ea, obj) == RULE_TRUE:
        return rule_exit(RULE_TRUE, ea, obj, "nav_import_several_functions")
    else:
        return rule_exit(RULE_FALSE)
