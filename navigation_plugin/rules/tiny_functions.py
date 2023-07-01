import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def one_line_function():
    pass

def two_line_function():
    pass

def rule_entry(ea, obj:FuncInfo):
    func_t_obj = ida_funcs.get_func(ea) 
    code_items = list(idautils.Heads(func_t_obj.start_ea, func_t_obj.end_ea))
    instr_num = len(code_items)
    if instr_num > 2:
        return False
    if instr_num == 1:
        one_line_function()
    if instr_num == 2:
        two_line_function()
        i1 = code_items[0]
        i2 = code_items[1]
        mnem = ida_ua.ua_mnem(i1)
        line = idc.GetDisasm(i1)
        print(ida_ua.ua_mnem(i1), "|", line)
        mnem = ida_ua.ua_mnem(i2)
        line = idc.GetDisasm(i2)
        print(ida_ua.ua_mnem(i2), "|", line)
    return False