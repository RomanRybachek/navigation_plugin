import idaapi
import idc

from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def check_RtlQueryRegistryValues(ea, obj:FuncInfo):
    if obj.import_calls_num != 3:
        return RULE_FALSE 
    if obj.loc_funcs_num != 2:
        return RULE_FALSE 
    if obj.has_cycle != True:
        return RULE_FALSE 
    if obj.strings_num != 1:
        return RULE_FALSE 

    s_ea = list(obj.strings)[0]
    s_type = idc.get_str_type(s_ea)
    s = idc.get_strlit_contents(s_ea, -1, s_type)
    if s == b"RtlQueryRegistryValuesEx":
        return RULE_TRUE
    else:
        return RULE_FALSE 

def rule_entry(ea, obj:FuncInfo):
    if check_RtlQueryRegistryValues(ea, obj) == RULE_TRUE:
        return rule_exit(RULE_TRUE, ea, obj, "nav_RtlQueryRegistryValues")
    else:
        return rule_exit(RULE_FALSE)
 
