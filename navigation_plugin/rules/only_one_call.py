import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def exectly_wrap(ea, obj:FuncInfo):
    func_t_obj = ida_funcs.get_func(ea) 
    code_items = list(idautils.Heads(func_t_obj.start_ea, func_t_obj.end_ea))
    if len(code_items) != 1:
        return False
    return True

def add_tag(tag, val, source_str):
    if val == 0:
        return source_str
    source_str = source_str + tag + str(val) + "_"
    return source_str

def rule_entry(ea, obj:FuncInfo):

    new_name = 'nav_'

    if  obj.calls != 1 or \
        obj.switches_num != 0 or \
        obj.has_cycle == True or \
        obj.loc_funcs_num != 0:

        return RULE_FALSE

    if exectly_wrap(ea, obj) == True:
        new_name += "wrap_"
    else:
        new_name += "call_"

    if obj.sub_funcs_num != 0:
        new_name += "unnamed_"
    elif obj.import_calls_num != 0:
        # print(obj.import_calls)
        new_name += ida_name.get_ea_name(list(obj.import_calls.keys())[0]) + "_"
    elif obj.named_funcs_num != 0:
        # print(obj.named_funcs)
        new_name += ida_name.get_ea_name(list(obj.named_funcs.keys())[0]) + "_"
    
    new_name = add_tag("d", obj.global_data, new_name)
    new_name = add_tag("s", obj.strings, new_name)

    if len(new_name) >= 1 and new_name[-1] == '_':
        new_name = new_name[:-1]

    idaapi.set_name(ea, new_name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
    return RULE_TRUE