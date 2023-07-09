import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def rule_entry(ea, obj:FuncInfo):
    func_t_obj = ida_funcs.get_func(ea) 
    code_items = list(idautils.Heads(func_t_obj.start_ea, func_t_obj.end_ea))
    instr_num = len(code_items)
    if instr_num > 5:
        return rule_exit(RULE_FALSE)
    
    new_name = 'nav_'

    for i in code_items:
        mnem = ida_ua.ua_mnem(i)
        if "ret" in mnem:
            break
        new_name += mnem + "_"

    new_name += get_info_for_name(ea, obj)

    if len(new_name) >= 1 and new_name[-1] == '_':
        new_name = new_name[:-1]
    return rule_exit(WEAK_RULE_TRUE, ea, obj, new_name) 