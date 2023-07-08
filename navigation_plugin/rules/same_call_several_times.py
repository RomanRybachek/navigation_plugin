import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def rule_entry(ea, obj:FuncInfo):
    if obj.calls <= 1:
        return RULE_FALSE
    
    num_groups_of_call = 0
    if obj.sub_funcs_num != 0:
        num_groups_of_call += 1
    if obj.named_funcs_num != 0:
        num_groups_of_call += 1
    if obj.import_calls_num != 0:
        num_groups_of_call += 1
    
    if num_groups_of_call != 1:
        return RULE_FALSE

    new_name = 'nav_'

    if len(obj.sub_funcs) == 1:
        count = list(obj.sub_funcs.values())[0]
        new_name += str(count) + "times_of_unnamed_"
    elif len(obj.named_funcs) == 1:
        count = list(obj.named_funcs.values())[0]
        func_name = ida_name.get_ea_name(list(obj.named_funcs.keys())[0])
        new_name += str(count) + "times_of_" + func_name + "_"
    elif len(obj.import_calls) == 1:
        count = list(obj.import_calls.values())[0]
        func_name = ida_name.get_ea_name(list(obj.import_calls.keys())[0])
        new_name += str(count) + "times_of_" + func_name + "_"
    else:
        return RULE_FALSE

    new_name = add_tag("loc", obj.loc_funcs_num, new_name)
    new_name = add_tag("switch", obj.switches_num, new_name)

    if obj.has_cycle == True:
        new_name = new_name + "cycle_"
    elif obj.hard_to_analyse == True:
        new_name = new_name + "cycleIsPossible_"

    new_name = add_tag("d", obj.global_data, new_name)
    new_name = add_tag("s", obj.strings_num, new_name)

    if len(new_name) >= 1 and new_name[-1] == '_':
        new_name = new_name[:-1]
    idaapi.set_name(ea, new_name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
    return RULE_TRUE